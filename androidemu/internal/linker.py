import logging
import os
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE, UcError

from ..const import emu_const
from ..data import layout as config
from ..types import ptr_t
from ..utils import misc_utils
from ..utils.memory.helpers import align_down, align_up, read_ptr_array
from ..utils.parsers.elf import ELFReader
from .bionic.tls.init import BionicTLSInitialization
from .module import Module
from .relocator import ARM32Relocator, ARM64Relocator
from .resolver import SymbolResolver
from .soinfo import SoinfoWriter

if TYPE_CHECKING:
    from ..core.emulator import Emulator

logger = logging.getLogger(__name__)


class AndroidLinker:
    """
    Bionic Dynamic Linker Orchestrator
    Lifecycle: Load Segments -> TLS Setup -> 3-Pass Relocations -> Init Constructors -> Memory Protect.
    """

    def __init__(self, emu: 'Emulator', vfs_root: str):
        self.emu = emu
        self.vfs_root = vfs_root

        self.modules: List[Module] = []
        self.modules_by_name: Dict[str, Module] = {}
        self.symbol_hooks: Dict[str, int] = {}

        self.resolver = SymbolResolver(self.symbol_hooks)

        self.soinfo_alloc_addr = config.SOINFO_START_BASE
        self.tls_area_size = config.TLS_SIZE
        self.tls: BionicTLSInitialization = self.emu.tls_state
        self.tls_initialized = False
        self._last_next_field_addr = 0

        try:
            emu.memory.map(config.TLS_BASE, self.tls_area_size, UC_PROT_READ | UC_PROT_WRITE)
            emu.memory.map(config.SOINFO_START_BASE, config.SOINFO_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        except UcError:
            pass

    def add_symbol_hook(self, symbol_name: str, addr: int) -> None:
        self.symbol_hooks[symbol_name] = addr
        self.resolver.invalidate_cache()

    def find_symbol_globally(self, symbol_name: str) -> int:
        res = self.resolver.resolve(symbol_name, all_modules=self.modules)
        return res.address if res.found else 0

    def find_function_by_name(self, symbol_name: str) -> int:
        for mod in self.modules:
            val = mod.find_function(symbol_name)
            if val:
                return val
        return 0

    def find_module_by_name(self, filename: str) -> Optional[Module]:
        basename = os.path.basename(filename)
        return self.modules_by_name.get(basename, None)

    def find_so_on_disk(self, so_path: str) -> Optional[str]:
        if os.path.isabs(so_path):
            return misc_utils.vfs_path_to_system_path(self.emu.vfs_root, so_path)

        ld_dirs = ["/system/lib/"] if self.emu.arch == emu_const.ARCH_ARM32 else ["/system/lib64/"]
        for lib_dir in ld_dirs:
            full_path = misc_utils.vfs_path_to_system_path(self.emu.vfs_root, f"{lib_dir}{so_path}")
            if os.path.exists(full_path):
                return full_path

        return None

    def load_module(self, filename: str, do_init: bool = True, main_lib: bool = False) -> Module:
        logger.info("[Linker] Request to load: %s (do_init=%s, main=%s)", filename, do_init, main_lib)

        start_idx = len(self.modules)
        target_module = self._load_recursive(filename)
        if not target_module:
            mod = self.find_module_by_name(filename)
            if mod:
                return mod
            raise RuntimeError(f"Could not load module: {filename}")

        target_module.main_executable = main_lib
        target_module.dynamic = not main_lib

        new_modules = self.modules[start_idx:]

        if not self.tls_initialized:
            self._bootstrap_tls(target_module)
        else:
            if self.tls:
                for mod in new_modules:
                    mod.tls_offset = self.tls.setup_static_tls(mod._reader, mod.bias)

        self.resolver.invalidate_cache()
        for mod in new_modules:
            self._relocate_module(mod)

        if do_init:
            self._initialize_graph(target_module)

        for mod in new_modules:
            self._protect_module(mod)
            mod._unload_reader()

        return target_module

    def _load_recursive(self, filename: str) -> Optional[Module]:
        path = self._resolve_path(filename)
        if not path:
            return None

        basename = os.path.basename(path)
        if basename in self.modules_by_name:
            return self.modules_by_name[basename]

        logger.debug("  [Load] Parsing %s", basename)
        reader = ELFReader(path)
        self._check_arch(reader, path)

        base, bias, size = self._map_elf_segments(reader)

        module = Module(path, base, bias, size, reader.dyn_addr, reader.exported_symbols, reader)
        self.modules.append(module)
        self.modules_by_name[basename] = module

        self._setup_soinfo(module, reader)

        for dep in reader.needed_libs:
            dep_mod = self._load_recursive(dep)
            if dep_mod:
                module.needed.append(dep_mod)

        return module

    def _bootstrap_tls(self, main_module: Module) -> None:
        if self.tls_initialized or not self.tls:
            return

        libc_mod = self.modules_by_name.get("libc.so")
        if not libc_mod:
            return

        entry_point = main_module.base + main_module._reader.entry_point
        self.tls.bootstrap(
            main_module.base + main_module._reader.phoff,
            main_module._reader.phdr_num,
            entry_point
        )

        for mod in self.modules:
            mod.tls_offset = self.tls.setup_static_tls(mod._reader, mod.bias)

        self.tls_initialized = True

    def _relocate_module(self, module: Module) -> None:
        logger.debug("  [Reloc] Applying 3-pass relocations to %s", os.path.basename(module.filename))
        is_64 = (self.emu.arch == emu_const.ARCH_ARM64)
        
        relocator_cls = ARM64Relocator if is_64 else ARM32Relocator
        relocator = relocator_cls(self.emu, module, self.resolver)
        relocator.relocate_all(self.modules)

    def _initialize_graph(self, root_module: Module) -> None:
        visited = set()

        def visit(mod: Module):
            if mod.initialized or mod in visited:
                return
            visited.add(mod)

            for dep in mod.needed:
                visit(dep)

            mod.initialized = True
            self.call_constructors(mod)

        visit(root_module)

    def call_constructors(self, module: Module) -> None:
        bias = module.bias
        mu = self.emu.mu
        logger.info("  [Init] Initializing %s", os.path.basename(module.filename))

        # 1. DT_PREINIT_ARRAY
        if module.main_executable:
            preinit_off = module.dynamic_tags.get("DT_PREINIT_ARRAY")
            preinit_sz = module.dynamic_tags.get("DT_PREINIT_ARRAYSZ")
            if preinit_off and preinit_sz:
                for func_va in read_ptr_array(mu, bias + preinit_off, preinit_sz):
                    self.emu.call_native(func_va)

        # 2. DT_INIT
        init = module.dynamic_tags.get("DT_INIT")
        if init:
            self.emu.call_native(bias + init)

        # 3. DT_INIT_ARRAY
        arr_off = module.dynamic_tags.get("DT_INIT_ARRAY")
        arr_sz = module.dynamic_tags.get("DT_INIT_ARRAYSZ")
        if arr_off and arr_sz:
            for func_va in read_ptr_array(mu, bias + arr_off, arr_sz):
                self.emu.call_native(func_va)

    def _setup_soinfo(self, module: 'Module', reader: 'ELFReader') -> None:
        info_ptr = self.soinfo_alloc_addr
        module.soinfo_ptr = info_ptr

        writer = SoinfoWriter(self.emu)
        current_next_field_ptr = writer.write_soinfo(module, reader, info_ptr)
        self.soinfo_alloc_addr += 0x400

        if self._last_next_field_addr:
            ptr_sz = ptr_t.size
            self.emu.mu.mem_write(self._last_next_field_addr, info_ptr.to_bytes(ptr_sz, 'little'))
        else:
            self._setup_linker_symbols(info_ptr)

        self._last_next_field_addr = current_next_field_ptr

    def _setup_linker_symbols(self, soinfo_head_ptr: int) -> None:
        ptr_sz = ptr_t.size
        linker_bin = "/system/bin/linker64" if self.emu.arch == emu_const.ARCH_ARM64 else "/system/bin/linker"
        linker_path = self.find_so_on_disk(linker_bin)

        if linker_path and os.path.exists(linker_path):
            linker_reader = ELFReader(linker_path)
            for sym_name in ["__dl__ZL6solist"]:
                sym_offset = linker_reader.get_symbol_address(sym_name)
                if sym_offset is not None:
                    target_addr = config.LINKER_BASE + sym_offset
                    self.emu.mu.mem_write(target_addr, soinfo_head_ptr.to_bytes(ptr_sz, 'little'))
                    break
            linker_reader.close()

    def _protect_module(self, module: 'Module') -> None:
        bias = module.bias

        for seg in module.segments:
            if seg['p_type'] != "LOAD":
                continue

            flags = seg.get('p_flags', 7)
            prot = 0
            if flags & 4: prot |= UC_PROT_READ
            if flags & 2: prot |= UC_PROT_WRITE
            if flags & 1: prot |= UC_PROT_EXEC

            start = align_down(bias + seg['p_vaddr'])
            size = align_up(bias + seg['p_vaddr'] + seg['p_memsz']) - start
            self.emu.memory.protect(start, size, prot)

        for seg in module.segments:
            if seg['p_type'] == "GNU_RELRO":
                relro_start = align_down(bias + seg['p_vaddr'])
                relro_end = align_down(bias + seg['p_vaddr'] + seg['p_memsz'])
                if relro_end > relro_start:
                    self.emu.memory.protect(relro_start, relro_end - relro_start, UC_PROT_READ)

    def _map_elf_segments(self, reader: 'ELFReader') -> Tuple[int, int, int]:
        load_segs = [s for s in reader.segments if s['p_type'] == "LOAD"]
        if not load_segs:
            raise RuntimeError("No LOAD segments found in ELF")

        min_v = min(s['p_vaddr'] for s in load_segs)
        max_v = max(s['p_vaddr'] + s['p_memsz'] for s in load_segs)

        aligned_min = align_down(min_v)
        aligned_max = align_up(max_v)
        total_span = aligned_max - aligned_min

        addr = self.emu.memory.find_free_region(size=total_span, start_search=config.BASE_ADDR)
        base = self.emu.memory.map(addr, total_span, prot=UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        bias = base - min_v

        for seg in load_segs:
            vaddr = seg['p_vaddr']
            memsz = seg['p_memsz']
            content = bytes(seg.get('content', b''))
            dest = bias + vaddr

            if content:
                self.emu.mu.mem_write(dest, content)

            file_sz = len(content)
            if memsz > file_sz:
                self.emu.mu.mem_write(dest + file_sz, b'\x00' * (memsz - file_sz))

        return base, bias, total_span

    def _resolve_path(self, filename: str) -> Optional[str]:
        if os.path.exists(filename):
            return filename

        is_64 = (self.emu.arch == emu_const.ARCH_ARM64)
        lib_dir = "lib64" if is_64 else "lib"
        marker = "arm64-v8a" if is_64 else "armeabi-v7a"
        base = os.path.basename(filename)

        paths = [
            f"/system/{lib_dir}/{base}",
            f"/vendor/{lib_dir}/{base}",
            f"/data/app/{self.emu.config.pkg.pkg_name}/lib/{marker}/{base}"
        ]

        for p in paths:
            real = misc_utils.vfs_path_to_system_path(self.vfs_root, p)
            if os.path.exists(real):
                return real

        return None

    def _check_arch(self, reader: 'ELFReader', path: str) -> None:
        is_32 = reader.is_32
        emu_32 = (self.emu.arch == emu_const.ARCH_ARM32)
        if is_32 != emu_32:
            raise RuntimeError(f"Arch mismatch: {path}. Expected {'ARM32' if emu_32 else 'ARM64'}")