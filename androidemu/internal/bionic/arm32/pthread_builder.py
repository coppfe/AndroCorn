import logging
from ....config import STACK_ADDR, STACK_SIZE
from ..pthread_builder import PThreadBuilder

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ....emulator import Emulator
    from ..tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class PThreadBuilderARM32(PThreadBuilder):
    def __init__(self, emu: 'Emulator', state: 'BionicTLS'):
        super().__init__(emu, state)

    def build(self, tls_slots_ptr: int, bionic_tls_ptr: int, dtv_ptr: int = 0) -> int:
        size = 0x400 
        base = self.state.mem_reserve(size, align=0x10)
        self.mu.mem_write(base, b"\x00" * size)

        # Offset 0x00: next
        # Offset 0x04: prev
        self._write_ptr(base + 0x00, base)
        self._write_ptr(base + 0x04, base)

        # Offset 0x08: tid (thread id)
        # Offset 0x0C: cached_pid_ (process id)
        tid = self.emu.tid
        pid = self.emu.pid
        self._write32(base + 0x08, tid)
        self._write32(base + 0x0C, pid)

        # Offset 0x10: stack_base
        # Offset 0x14: stack_size
        self._write_ptr(base + 0x10, STACK_ADDR) 
        self._write_ptr(base + 0x14, STACK_SIZE)
        # Offset 0x18: guard_size (0)
        self._write32(base + 0x18, 0)

        # Offset 0x1C: join_state (0 = DETACHED)
        self._write32(base + 0x1C, 0)

        # DTV Pointer
        if dtv_ptr:
            self._write_ptr(base + 0x30, dtv_ptr)

        # Offset 0x34: bionic_tls
        if bionic_tls_ptr:
            self._write_ptr(base + 0x34, bionic_tls_ptr)

        self._write_ptr(base + 0x28, tls_slots_ptr)

        self.state.pthread_internal = base
        logger.debug(
            f"[PThread-7.1-ARM32] Built at {hex(base)}. "
            f"TID: {tid}, DTV: {hex(dtv_ptr)} at +0x30"
        )
        
        return base

    def _write_ptr(self, addr, val):
        self.mu.mem_write(addr, val.to_bytes(4, 'little'))

    def _write32(self, addr, val):
        self.mu.mem_write(addr, val.to_bytes(4, 'little'))