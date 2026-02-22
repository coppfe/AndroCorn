import logging
from ....config import STACK_ADDR, STACK_SIZE
from ..pthread_builder import PThreadBuilder

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ....emulator import Emulator
    from ..tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class PThreadBuilderARM64(PThreadBuilder):
    """
    Реализация pthread_internal_t для ARM64 (Modern Android 9+ Layout).
    Смещения и структура адаптированы под 64-бит.
    """

    def __init__(self, emu: 'Emulator', state: 'BionicTLS'):
        super().__init__(emu, state)

    def build(self, tls_slots_ptr: int, bionic_tls_ptr: int, dtv_ptr: int = 0) -> int:
        size = 0x400
        base = self.state.mem_reserve(size, align=0x10)
        self.mu.mem_write(base, b"\x00" * size)

        # Offset 0x00: next
        # Offset 0x08: prev
        self._write_ptr(base + 0x00, base)
        self._write_ptr(base + 0x08, base)

        # Offset 0x10: tid
        # Offset 0x18: cached_pid_
        tid = self.emu.tid
        pid = self.emu.pid
        self._write_ptr(base + 0x10, tid)
        self._write_ptr(base + 0x18, pid)

        # Stack Info (pthread_attr_t)
        # Offset 0x20: stack_base
        # Offset 0x28: stack_size
        self._write_ptr(base + 0x20, STACK_ADDR)
        self._write_ptr(base + 0x28, STACK_SIZE)
        # Offset 0x30: guard_size (0)
        self._write_ptr(base + 0x30, 0)

        # Offset 0x38: join_state (0 = DETACHED)
        self._write_ptr(base + 0x38, 0)

        # DTV Pointer
        # Offset 0x60: DTV
        if dtv_ptr:
            self._write_ptr(base + 0x60, dtv_ptr)

        # Bionic TLS
        # Offset 0x68: bionic TLS
        if bionic_tls_ptr:
            self._write_ptr(base + 0x68, bionic_tls_ptr)

        # TLS Slots pointer (TP)
        # Offset 0x50: tls slots link
        self._write_ptr(base + 0x50, tls_slots_ptr)

        self.state.pthread_internal = base
        logger.debug(
            f"[PThread-ARM64] Built at {hex(base)}. "
            f"TID: {tid}, DTV: {hex(dtv_ptr)} at +0x60"
        )

        return base