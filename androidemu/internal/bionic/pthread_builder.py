import logging
from abc import ABC, abstractmethod
from ...config import STACK_ADDR, STACK_SIZE

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator
    from .tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class PThreadBuilder(ABC):
    def __init__(self, emu: 'Emulator', state: 'BionicTLS'):
        self.emu = emu
        self.mu = emu.mu
        self.state = state
        self.ptr_sz = emu.get_ptr_size()

    @abstractmethod
    def build(self, tls_slots_ptr: int, bionic_tls_ptr: int, dtv_ptr: int = 0) -> int:
        raise NotImplementedError()

    # --- Helpers ---

    def _write_ptr(self, addr, val: int):
        self.mu.mem_write(addr, val.to_bytes(self.ptr_sz, 'little'))

    def _write32(self, addr, val: int):
        self.mu.mem_write(addr, val.to_bytes(4, 'little'))