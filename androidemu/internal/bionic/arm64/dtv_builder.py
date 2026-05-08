import logging
from ..dtv_builder import DTVBuilder
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ....emulator import Emulator
    from .tls_bootstrap import BionicTLS_ARM64

logger = logging.getLogger(__name__)

class DTVBuilderARM64(DTVBuilder):
    """
    Dumb & Fast DTV (Dynamic Thread Vector) Builder for ARM64.
    
    Layout:
      dtv[0] : Generation
      dtv[1] : Module Count
      dtv[2..N] : Module Pointers
    """

    def __init__(self, emu: 'Emulator', tls: 'BionicTLS_ARM64') -> None:
        super().__init__(emu, tls)

    def build(self) -> int:
        """Allocate the entire DTV table once."""
        # (2 header slots + MAX_MODULES) * 8 bytes
        size = (2 + self.MAX_MODULES) * self.ptr_sz
        
        self.base = self.emu.memory.static_alloc(size, align=0x10)

        self._write_ptr(self.base, self.dtv_generation)
        self._write_ptr(self.base + self.ptr_sz, self.module_count)
        
        self.state.dtv = self.base
        logger.debug("[DTV-ARM64] Built at %#x", self.base)
        return self.base

    def register_module(self, tls_block_ptr: int) -> int:
        """Register a module and update the DTV headers."""
        if self.module_count >= self.MAX_MODULES:
            raise RuntimeError("DTV ARM64: Out of slots (max 256)")

        self.module_count += 1
        module_id = self.module_count

        self._write_ptr(self.base + self.ptr_sz, self.module_count)

        # (id + 1) because dtv[0]=gen, dtv[1]=count, dtv[2]=mod1...
        entry_addr = self.base + (module_id + 1) * self.ptr_sz
        self._write_ptr(entry_addr, tls_block_ptr)

        self.dtv_generation += 1
        self._write_ptr(self.base, self.dtv_generation)

        logger.debug("[DTV-ARM64] Registered mod_id=%d -> block=%#x", module_id, tls_block_ptr)
        return module_id

    def get_tls_block(self, module_id: int) -> int:
        """Read back a TLS block address from the DTV."""
        addr = self.base + (module_id + 1) * self.ptr_sz
        return self._read_ptr(addr)

    def _write_ptr(self, addr: int, val: int):
        self.mu.mem_write(addr, val.to_bytes(self.ptr_sz, 'little'))

    def _read_ptr(self, addr: int) -> int:
        return int.from_bytes(self.mu.mem_read(addr, self.ptr_sz), 'little')