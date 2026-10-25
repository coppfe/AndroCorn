import logging
import os
from typing import TYPE_CHECKING, Dict

from ...const import emu_const
from ...data import layout as config
from ...types import ptr_t
from ...utils.parsers.elf import ELFReader
from .soinfo import SoinfoWriter

if TYPE_CHECKING:
    from ...core.emulator import Emulator
    from ...internal.module import Module
    from .libres import LibraryResolver

logger = logging.getLogger(__name__)


class BionicLinkerRuntime:

    def __init__(self, emu: 'Emulator', lib_resolver: 'LibraryResolver'):
        self.emu = emu
        self.mem = emu.memory
        self.resolver = lib_resolver
        self.ptr_sz = ptr_t.size

        self.soinfo_alloc_addr = config.SOINFO_START_BASE
        self.head_soinfo: int = 0
        self.tail_soinfo: int = 0
        self.main_soinfo: int = 0

        self._last_next_field_addr: int = 0
        self._linker_symbols: Dict[str, int] = {}

        # r_debug / link_map
        self._r_debug_addr: int = 0
        self._last_link_map_addr: int = 0

        self._init_linker_image_symbols()
        self._init_r_debug()

    def _init_linker_image_symbols(self) -> None:
        is_64 = (self.emu.arch == emu_const.ARCH_ARM64)
        linker_bin = "/system/bin/linker64" if is_64 else "/system/bin/linker"
        linker_path = self.resolver.find_so_on_disk(linker_bin)

        if not linker_path or not os.path.exists(linker_path):
            logger.warning("[LinkerRuntime] Linker binary '%s' not found on VFS", linker_bin)
            return

        reader = ELFReader(linker_path)
        target_symbols = [
            "__dl__ZL6solist",
            "__dl__ZL7sonext",
            "__dl__ZL4somain",
            "__dl__r_debug",
            "_r_debug"
        ]

        for sym in target_symbols:
            off = reader.get_symbol_address(sym)
            if off is not None:
                self._linker_symbols[sym] = config.LINKER_BASE + off
                logger.debug("[LinkerRuntime] Located symbol %s at 0x%08X", sym, self._linker_symbols[sym])

        reader.close()

    def _init_r_debug(self) -> None:
        """
        struct r_debug {
            int32_t r_version;
            struct link_map* r_map;
            void (*r_brk)(void);
            int32_t r_state;
            uintptr_t r_ldbase;
        };
        """
        self._r_debug_addr = self.mem.static_alloc(0x100, align=0x10)
        self.mem.write_u32(self._r_debug_addr, 1)                      # r_version = 1
        self.mem.write_ptr(self._r_debug_addr + self.ptr_sz, 0)        # r_map = NULL
        self.mem.write_ptr(self._r_debug_addr + 4 * self.ptr_sz, config.LINKER_BASE) # r_ldbase

        for sym in ("__dl__r_debug", "_r_debug"):
            if sym in self._linker_symbols:
                self.mem.write_ptr(self._linker_symbols[sym], self._r_debug_addr)

    def register_module(self, module: 'Module', reader: 'ELFReader') -> int:
        info_ptr = self.soinfo_alloc_addr
        module.soinfo_ptr = info_ptr

        writer = SoinfoWriter(self.emu)
        current_next_field_ptr = writer.write_soinfo(module, reader, info_ptr)
        self.soinfo_alloc_addr += 0x400

        if not self.head_soinfo:
            self.head_soinfo = info_ptr
            if "__dl__ZL6solist" in self._linker_symbols:
                self.mem.write_ptr(self._linker_symbols["__dl__ZL6solist"], info_ptr)
        else:
            if self._last_next_field_addr:
                self.mem.write_ptr(self._last_next_field_addr, info_ptr)

        self._last_next_field_addr = current_next_field_ptr
        self.tail_soinfo = info_ptr

        if "__dl__ZL7sonext" in self._linker_symbols:
            self.mem.write_ptr(self._linker_symbols["__dl__ZL7sonext"], info_ptr)

        if module.main_executable:
            self.main_soinfo = info_ptr
            if "__dl__ZL4somain" in self._linker_symbols:
                self.mem.write_ptr(self._linker_symbols["__dl__ZL4somain"], info_ptr)

        self._add_to_link_map(module)

        return info_ptr

    def _add_to_link_map(self, module: 'Module') -> None:
        """
        struct link_map {
            uintptr_t l_addr;   // Module base
            uintptr_t l_name;   // Pointer to filename string
            uintptr_t l_ld;     // Dynamic section
            link_map* l_next;
            link_map* l_prev;
        };
        """
        lm_size = 5 * self.ptr_sz
        lm_ptr = self.mem.static_alloc(lm_size, align=0x8)

        self.mem.write_ptr(lm_ptr + 0 * self.ptr_sz, module.base)
        self.mem.write_ptr(lm_ptr + 1 * self.ptr_sz, module.filename_ptr)
        self.mem.write_ptr(lm_ptr + 2 * self.ptr_sz, module.dynamic)
        self.mem.write_ptr(lm_ptr + 3 * self.ptr_sz, 0) # next = NULL
        self.mem.write_ptr(lm_ptr + 4 * self.ptr_sz, self._last_link_map_addr) # prev

        if not self._last_link_map_addr:
            self.mem.write_ptr(self._r_debug_addr + self.ptr_sz, lm_ptr)
        else:
            self.mem.write_ptr(self._last_link_map_addr + 3 * self.ptr_sz, lm_ptr)

        self._last_link_map_addr = lm_ptr