import logging
from ..dtv_builder import DTVBuilder
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ....emulator import Emulator
    from .tls_bootstrap import BionicTLS_ARM64

logger = logging.getLogger(__name__)

class DTVBuilderARM64(DTVBuilder):
    """
    Layout (64-бит):
      [0] Generation
      [1] Module Count
      [2] Module 1 Ptr
      [3] Module 2 Ptr
      ...
    """

    def __init__(self, emu: 'Emulator', tls: 'BionicTLS_ARM64') -> None:
        super().__init__(emu, tls)

    def build(self) -> int:
        size = (2 + self.max_modules) * self.ptr_sz
        base = self.state.mem_reserve(size, align=0x10)

        self.base = base
        self.dtv_generation = 1
        self.module_count = 0

        self._write_ptr(base, self.dtv_generation)
        self._write_ptr(base + self.ptr_sz, self.module_count)

        rest_size = size - (2 * self.ptr_sz)
        if rest_size > 0:
            self.mu.mem_write(base + 2 * self.ptr_sz, b'\x00' * rest_size)

        self.state.dtv = base
        logger.debug(f"[DTV-ARM64] Built at {hex(base)}")
        return base

    def register_module(self, tls_block: int) -> int:
        self.module_count += 1
        module_id = self.module_count

        count_addr = self.base + self.ptr_sz
        self._write_ptr(count_addr, self.module_count)

        entry_addr = self.base + (module_id + 1) * self.ptr_sz
        self._write_ptr(entry_addr, tls_block)

        self.dtv_generation += 1
        self._write_ptr(self.base, self.dtv_generation)

        logger.debug(f"[DTV-ARM64] Registered mod_id={module_id} block={hex(tls_block)} at {hex(entry_addr)}")
        return module_id

    def get_tls_block(self, module_id: int) -> int:
        # addr = base + (id + 1) * ptr_sz
        addr = self.base + (module_id + 1) * self.ptr_sz
        return self._read_ptr(addr)

    def register_static(self, tls_block: int) -> int:
        return self.register_module(tls_block)

    def register_dynamic(self, tls_block: int) -> int:
        return self.register_module(tls_block)