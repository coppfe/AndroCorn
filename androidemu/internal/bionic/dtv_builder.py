import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...emulator import Emulator
    from .tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class DTVBuilder(ABC):
    def __init__(self, emu: 'Emulator', state):
        self.emu = emu
        self.mu = emu.mu
        self.state: 'BionicTLS' = state
        self.ptr_sz = emu.get_ptr_size()
        
        self.base = 0
        self.max_modules = 64
        self.dtv_generation = 0
        self.module_count = 0

    @abstractmethod
    def build(self) -> int:
        pass

    @abstractmethod
    def register_module(self, tls_block: int) -> int:
        pass

    @abstractmethod
    def get_tls_block(self, module_id: int) -> int:
        pass

    # --- Helpers ---
    
    def _write_ptr(self, addr: int, val: int):
        self.mu.mem_write(addr, val.to_bytes(self.ptr_sz, 'little'))

    def _read_ptr(self, addr: int):
        return int.from_bytes(self.mu.mem_read(addr, self.ptr_sz), 'little')
