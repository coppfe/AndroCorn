import logging

from typing import TYPE_CHECKING

from ...types.alias import ptr_t

if TYPE_CHECKING:
    from androidemu.internal.bionic.tls.init import BionicTLSInitialization
    from androidemu.utils.memory.map import MemoryMap
    from unicorn import Uc

logger = logging.getLogger(__name__)

class DTVBuilder:
    """
    Dumb & Fast DTV (Dynamic Thread Vector) Builder.
    Matches ARM64 layout for consistency.
    
    Layout:
      dtv[0] : Generation
      dtv[1] : Module Count
      dtv[2..N] : Module Pointers
    """

    MAX_MODULES = 256

    def __init__(self, memory: 'MemoryMap', mu: 'Uc', tls: 'BionicTLSInitialization') -> None:
        self.mu = mu
        self.memory = memory
        self.tls = tls

        self.base = 0
        self.dtv_generation = 0
        self.module_count = 0

        self.ptr_sz = ptr_t.size

        self.state = tls

    def build(self) -> int:
        """Allocate the entire DTV table once."""
        # (2 header slots + MAX_MODULES) * sizeof(ptr_t) bytes
        size = (2 + self.MAX_MODULES) * self.ptr_sz
        
        self.base = self.memory.static_alloc(size, align=0x10)

        self._write_ptr(self.base, self.dtv_generation)              # dtv[0]
        self._write_ptr(self.base + self.ptr_sz, 0)                  # dtv[1] (count)
        
        self.state.dtv = self.base
        logger.debug("[DTV] Built at %#x", self.base)
        return self.base

    def register_module(self, tls_block_ptr: int) -> int:
        """Register a module and update the DTV headers."""
        if self.module_count >= self.MAX_MODULES:
            raise RuntimeError(f"DTV: Out of slots (max {self.MAX_MODULES})")

        self.module_count += 1
        module_id = self.module_count

        self._write_ptr(self.base + self.ptr_sz, self.module_count)

        # (module_id + 1) ensures mod_id 1 starts at dtv[2]
        # index 0: gen, index 1: count, index 2: mod 1...
        entry_addr = self.base + (module_id + 1) * self.ptr_sz
        self._write_ptr(entry_addr, tls_block_ptr)

        # Update [slot 0]
        self.dtv_generation += 1
        self._write_ptr(self.base, self.dtv_generation)

        logger.debug("[DTV] Registered mod_id=%d -> block=%#x", module_id, tls_block_ptr)
        return module_id

    def get_tls_block(self, module_id: int) -> int:
        """Read back a TLS block address from the DTV."""
        addr = self.base + (module_id + 1) * self.ptr_sz
        return self._read_ptr(addr)

    def _write_ptr(self, addr: int, val: int):
        self.mu.mem_write(addr, val.to_bytes(self.ptr_sz, 'little'))

    def _read_ptr(self, addr: int) -> int:
        return int.from_bytes(self.mu.mem_read(addr, self.ptr_sz), 'little')