import logging
import os
from typing import List, Dict, Optional, Tuple, TYPE_CHECKING

from unicorn import UC_PROT_READ, UC_PROT_WRITE, UcError
from unicorn.arm_const import *
from unicorn.arm64_const import *

from lief.ELF import Relocation

from ..const import emu_const
from .. import config
from ..utils import memory_helpers, misc_utils
from .module import Module
from .elf_reader import ELFReader
from .soinfo import SoinfoWriter
from .relocator import ARM32Relocator, ARM64Relocator, Relocation
from .bionic.tls_bionic import BionicTLS

if TYPE_CHECKING:
    from ..emulator import Emulator

logger = logging.getLogger(__name__)

class AndroidLinker:
    """
    High-precision Android 7.1 (Nougat) Dynamic Linker emulation.
    Refactored for strict phase separation: Load -> Bootstrap -> Relocate -> Init.
    
    Maybe will be work on Android 9 system libs...
    """

    def __init__(self, emu: 'Emulator', vfs_root: str):
        self.emu = emu
        self.vfs_root = vfs_root
        
        # --- Storage ---
        self.modules: List[Module] = []           
        self.modules_by_name: Dict[str, Module] = {} 
        self.symbol_hooks: Dict[str, int] = {}

        # --- Memory Allocators ---
        self.current_mmap_addr = config.BASE_ADDR
        self.soinfo_alloc_addr = config.SOINFO_START_BASE
        self.tls_area_size = config.TLS_SIZE

        # --- State ---
        self.tls: BionicTLS = self.emu.tls_state
        self.tls_initialized = False
        self._last_next_field_addr = 0 # For soinfo linked list
        
        try:
            emu.memory.map(config.TLS_BASE, self.tls_area_size, UC_PROT_READ | UC_PROT_WRITE)
            emu.memory.map(config.SOINFO_START_BASE, 
                                         config.SOINFO_SIZE, 
                                         UC_PROT_READ | UC_PROT_WRITE)
        except UcError:
            pass
    # =========================================================================
    # Public API (Compatibility Layer for Emulator)
    # =========================================================================

    def add_symbol_hook(self, symbol_name: str, addr: int) -> None:
        self.symbol_hooks[symbol_name] = addr

    def find_symbol_globally(self, symbol_name: str) -> int:
        # 1. Hooks
        if symbol_name in self.symbol_hooks:
            return self.symbol_hooks[symbol_name]
        
        # 2. Linear Search
        #O(n**2)
        #TODO: improve

        for mod in self.modules:
            val = mod.find_symbol(symbol_name)
            if val: return val
        return 0
    
    def find_function_by_name(self, symbol_name: str) -> Optional[Module]:
        for mod in self.modules:
            val = mod.find_function(symbol_name)
            if val: return val
        return 0

    def find_module_by_name(self, filename: str) -> Optional[Module]:
        """Legacy wrapper."""
        basename = os.path.basename(filename)
        return self.modules_by_name.get(basename)
    
    def __get_ld_library_path(self):
        if (self.emu.get_arch() == emu_const.ARCH_ARM32):
            return ["/system/lib/"]
        else:
            return ["/system/lib64/"]
    #

    def find_so_on_disk(self, so_path):
        if os.path.isabs(so_path):
            path = misc_utils.vfs_path_to_system_path(self.emu.get_vfs_root(), so_path)
            return path
        else:
            ld_library_path = self.__get_ld_library_path()
            so_name = so_path
            for lib_path in ld_library_path:
                lib_full_path = "%s/%s"%(lib_path, so_name)
                vfs_lib_path = misc_utils.vfs_path_to_system_path(self.emu.get_vfs_root(), lib_full_path)
                if (os.path.exists(vfs_lib_path)):
                    return vfs_lib_path
                #
            #
        #
        return None

    def load_module(self, filename: str, do_init: bool = True, main_lib: bool = False) -> Module:
        """
        Main entry point called by Emulator.
        Handles both the initial executable load and subsequent dlopens.
        """
        logger.info(f"[Linker] Request to load: {filename} (do_init={do_init}) (main={main_lib})")
        
        if not self.tls_initialized:
            return self._pipeline_load_executable(filename)
        else:
            return self._pipeline_dlopen(filename, do_init)

    # =========================================================================
    # Core Pipelines
    # =========================================================================

    def _pipeline_load_executable(self, filename: str) -> Module:
        """Pipeline for the initial process startup."""
        logger.info("=== [Linker Phase 1] Loading Dependencies ===")
        main_module = self._load_recursive(filename)
        if not main_module:
            raise RuntimeError(f"Could not load {filename}")

        logger.info("=== [Linker Phase 2] TLS Bootstrap ===")
        self._bootstrap_tls(main_module)

        logger.info("=== [Linker Phase 3] Relocations ===")
        for mod in self.modules:
            self._relocate_module(mod)

        logger.info("=== [Linker Phase 4] Constructors ===")

        self.emu.sym_hooks.init_fun_hooks()
        self._initialize_graph(main_module)
        
        return main_module

    def _pipeline_dlopen(self, filename: str, do_init: bool) -> Module:
        """Pipeline for dynamic loading after startup."""
        
        # Load new modules
        start_index = len(self.modules)
        new_module = self._load_recursive(filename)
        
        if not new_module:
            # Already loaded?
            m = self.find_module_by_name(filename)
            if m: return m
            else: raise RuntimeError(f"dlopen failed: {filename}")

        new_modules_list = self.modules[start_index:]
        
        if self.tls:
            for mod in new_modules_list:
                mod.tls_offset = self.tls.setup_static_tls(mod.reader, mod.bias)
                logger.debug(f"[Linker] Dynamic TLS registered for {os.path.basename(mod.filename)}")
        
        for mod in new_modules_list:
            self._relocate_module(mod)
        
        # 3. Initialize ONLY new modules
        if do_init:
            self._initialize_graph(new_module)
            
        return new_module

    # =========================================================================
    # Internal Logic
    # =========================================================================

    def _load_recursive(self, filename: str) -> Optional[Module]:
        path = self._resolve_path(filename)
        if not path:
            return None

        basename = os.path.basename(path)
        if basename in self.modules_by_name:
            return self.modules_by_name[basename]

        logger.debug(f"  [Load] Parsing {basename}")
        reader = ELFReader(path)
        self._check_arch(reader, path)
        
        # Map
        base, bias, size = self._map_elf_segments(reader)
        
        # Create Module
        module = Module(path, base, bias, size, reader.exported_symbols, reader)
        
        # Register immediately to prevent recursion loops
        self.modules.append(module)
        self.modules_by_name[basename] = module
        
        # Setup Soinfo
        self._setup_soinfo(module, reader)

        # Load Dependencies
        for dep in reader.needed_libs:
            dep_mod = self._load_recursive(dep)
            if dep_mod:
                module.needed.append(dep_mod)
        
        return module

    def _bootstrap_tls(self, main_module: Module):
        if self.tls_initialized: return
        
        libc_mod = self.modules_by_name.get("libc.so")
        if not libc_mod: return

        entry_point = main_module.base + main_module.reader.entry_point
        self.tls.bootstrap(
            main_module.base + main_module.reader.phoff,  # phdr_addr
            main_module.reader.phdr_num,                  # phnum
            entry_point
        )
        
        for mod in self.modules:
            mod.tls_offset = self.tls.setup_static_tls(mod.reader, mod.bias)
        
            logger.info(f"  [TLS] Bootstrap done for {os.path.basename(mod.filename)}. TLS offset: {hex(mod.tls_offset)}")

        self.tls_initialized = True

    def _relocate_module(self, module: Module):
        logger.debug(f"  [Reloc] Applying to {os.path.basename(module.filename)}")
        reader = module.reader
        bias = module.bias

        is_64 = not reader.is_32

        relocator = ARM64Relocator(self.emu, bias) if is_64 else ARM32Relocator(self.emu, bias)
        logger.debug(f"  [Reloc] Relocations: {len(reader.relocations)}. is_64: {is_64}. Bias: {hex(bias)}")
        for rel in reader.relocations:
            r_type = rel.type
            r_addr = bias + rel.address
            
            sym_addr = 0
            sym_name = None
            sym_tls_off = 0
            
            if rel.has_symbol:
                sym_name = rel.symbol.name
                sym_addr = self.find_symbol_globally(sym_name)

                if self.tls:
                    for m in self.modules:
                        if m.find_symbol(sym_name):
                            sym_tls_off = getattr(m, 'tls_offset', 0)
                            break

            addend = getattr(rel, "addend", 0) if is_64 else int.from_bytes(self.emu.mu.mem_read(r_addr, 4), 'little')
            tls_ctx = {"tp": self.tls.tp, "offset": sym_tls_off} if self.tls else None
            
            try:
                relocator.apply(r_type, r_addr, sym_addr, sym_name, addend, tls_ctx)
            except Exception as e:
                # logger.warning(f"Relocation error {sym_name}: {e}")
                pass

    def _initialize_graph(self, root_module: Module):
        """DFS Init"""
        visited = set()
        
        def visit(mod: Module):
            if mod in visited or mod.initialized:
                return
            visited.add(mod)
            
            for dep in mod.needed:
                visit(dep)
            
            self._call_constructors(mod)
            mod.initialized = True
            
        visit(root_module)

    def _call_constructors(self, module: Module):
        reader = module.reader
        bias = module.bias
        ptr_sz = self.emu.get_ptr_size()
        
        logger.info(f"  [Init] {os.path.basename(module.filename)}")

        # DT_INIT
        init = reader._dynamic_tags.get("DT_INIT")
        if init:
            self.emu.call_native(bias + init)
            
        # DT_INIT_ARRAY
        arr_off = reader._dynamic_tags.get("DT_INIT_ARRAY")
        arr_sz = reader._dynamic_tags.get("DT_INIT_ARRAYSZ")

        if arr_off and arr_sz:
            count = arr_sz // ptr_sz
            start = bias + arr_off
            for i in range(count):
                func_va = int.from_bytes(self.emu.mu.mem_read(start + i*ptr_sz, ptr_sz), 'little')
                # Ignore empty slots (0 or -1)
                if func_va not in (0, 2**(ptr_sz*8)-1):
                    self.emu.call_native(func_va)

    def _setup_soinfo(self, module: Module, reader: ELFReader):
        info_ptr = self.soinfo_alloc_addr
        module.soinfo_ptr = info_ptr
        writer = SoinfoWriter(self.emu)
        next_field_addr = writer.write_soinfo(module, reader)
        
        self.soinfo_alloc_addr += next_field_addr - info_ptr
        logger.debug(f"[*] soinfo: {hex(info_ptr)} for {module.filename}. Current alloc: {hex(self.soinfo_alloc_addr)}.")

        # Link previous
        if self._last_next_field_addr:
            ptr_sz = self.emu.get_ptr_size()
            self.emu.mu.mem_write(self._last_next_field_addr, info_ptr.to_bytes(ptr_sz, 'little'))

        logger.debug(f"[*] soinfo: {hex(info_ptr)} for {module.filename}. Next: {hex(next_field_addr)}. Size: {hex(next_field_addr - info_ptr)}.")

        self._last_next_field_addr = next_field_addr

    def _map_elf_segments(self, reader: ELFReader) -> Tuple[int, int, int]:
        page_sz = config.PAGE_SIZE
        load_segs = [s for s in reader.segments if s['p_type'] == 'LOAD']
        
        min_v = min(s['p_vaddr'] for s in load_segs)
        max_v = max(s['p_vaddr'] + s['p_memsz'] for s in load_segs)
        
        align_start = min_v & ~(page_sz - 1)
        align_end = (max_v + page_sz - 1) & ~(page_sz - 1)
        size = align_end - align_start
        
        base = memory_helpers.mem_reserve(self.emu.mu, self.current_mmap_addr, self.current_mmap_addr + size, config.PAGE_SIZE)
        self.current_mmap_addr = (base + size + 0x10000) & ~0xFFFF
        bias = base - align_start
        
        for seg in load_segs:
            dest = bias + seg['p_vaddr']
            content = seg['content']
            if content:
                self.emu.mu.mem_write(dest, bytes(content))
            
            # BSS
            if seg['p_memsz'] > len(content):
                self.emu.mu.mem_write(dest + len(content), b'\x00' * (seg['p_memsz'] - len(content)))
        
        logger.debug(f"[*] ELF mapped to {hex(base)}. Size: {hex(size)}. Bias: {hex(bias)}. Segments: {len(load_segs)}. Min: {hex(min_v)}, Max: {hex(max_v)}")
        return base, bias, size

    def _resolve_path(self, filename: str) -> Optional[str]:
        if os.path.exists(filename): return filename
        
        is_64 = (self.emu.get_arch() == emu_const.ARCH_ARM64)
        lib_dir = "lib64" if is_64 else "lib"
        
        base = os.path.basename(filename)
        paths = [
            f"/system/{lib_dir}/{base}",
            f"/vendor/{lib_dir}/{base}",
            f"/data/local/tmp/{base}"
        ]
        
        for p in paths:
            # Conversion VFS -> Real OS path
            real = misc_utils.vfs_path_to_system_path(self.vfs_root, p)
            if os.path.exists(real): return real
            
        return None

    def _check_arch(self, reader: 'ELFReader', path):
        is_32 = reader.is_32
        emu_32 = (self.emu.get_arch() == emu_const.ARCH_ARM32)
        if is_32 != emu_32:
            raise RuntimeError(f"Arch mismatch: {path}. Expected {emu_const.ARCH_ARM32 if is_32 else emu_const.ARCH_ARM64}, got {self.emu.get_arch()}.")