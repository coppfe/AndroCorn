import logging
import os
from typing import TYPE_CHECKING, Dict, List, Optional

from unicorn import UC_PROT_READ, UC_PROT_WRITE, UcError

from ...data import layout as config
from ...utils.memory.helpers import read_ptr_array
from ...utils.parsers.elf import ELFReader
from ..bionic.tls.init import BionicTLSInitialization
from ..module import Module
from ..relocator import ARM32Relocator, ARM64Relocator
from ..resolver import SymbolResolver
from .libres import LibraryResolver
from .elfmap import ELFMapper
from .runtime import BionicLinkerRuntime

if TYPE_CHECKING:
    from ...core.emulator import Emulator

logger = logging.getLogger(__name__)


class AndroidLinker:
    """
    Bionic Dynamic Linker Orchestrator
    Lifecycle: Resolve -> Map Segments -> TLS Setup -> Relocate -> Constructors -> Protect.
    """

    def __init__(self, emu: 'Emulator', vfs_root: str):
        self.emu = emu
        self.vfs_root = vfs_root

        self.modules: List[Module] = []
        self.modules_by_name: Dict[str, Module] = {}
        self.symbol_hooks: Dict[str, int] = {}

        self.resolver = SymbolResolver(self.symbol_hooks)
        self.path_resolver = LibraryResolver(emu, vfs_root)
        self.mapper = ELFMapper(emu)
        self.runtime = BionicLinkerRuntime(emu, self.path_resolver)

        self.tls: BionicTLSInitialization = self.emu.tls_state
        self.tls_initialized = False

        try:
            emu.memory.map(config.TLS_BASE, config.TLS_SIZE, UC_PROT_READ | UC_PROT_WRITE)
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
        return self.path_resolver.find_so_on_disk(so_path)

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
            self.mapper.protect_module(mod)
            mod._unload_reader()

        return target_module

    def _load_recursive(self, filename: str) -> Optional[Module]:
        path = self.path_resolver.resolve(filename)
        if not path:
            return None

        basename = os.path.basename(path)
        if basename in self.modules_by_name:
            return self.modules_by_name[basename]

        logger.debug("  [Load] Parsing %s", basename)
        reader = ELFReader(path)
        self.path_resolver.check_arch(reader, path)

        base, bias, size = self.mapper.map_segments(reader)

        module = Module(path, base, bias, size, reader.dyn_addr, reader.exported_symbols, reader)
        self.modules.append(module)
        self.modules_by_name[basename] = module

        self.runtime.register_module(module, reader)

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
        is_64 = (self.emu.arch == 2)  # ARCH_ARM64
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
        mem = self.emu.memory
        logger.info("  [Init] Initializing %s", os.path.basename(module.filename))

        # 1. DT_PREINIT_ARRAY
        if module.main_executable:
            preinit_off = module.dynamic_tags.get("DT_PREINIT_ARRAY")
            preinit_sz = module.dynamic_tags.get("DT_PREINIT_ARRAYSZ")
            if preinit_off and preinit_sz:
                for func_va in read_ptr_array(mem, bias + preinit_off, preinit_sz):
                    self.emu.call_native(func_va)

        # 2. DT_INIT
        init = module.dynamic_tags.get("DT_INIT")
        if init:
            self.emu.call_native(bias + init)

        # 3. DT_INIT_ARRAY
        arr_off = module.dynamic_tags.get("DT_INIT_ARRAY")
        arr_sz = module.dynamic_tags.get("DT_INIT_ARRAYSZ")
        if arr_off and arr_sz:
            for func_va in read_ptr_array(mem, bias + arr_off, arr_sz):
                self.emu.call_native(func_va)