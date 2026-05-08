import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...emulator import Emulator
    from .tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class DTVBuilder(ABC):

    MAX_MODULES = 256 
    
    def __init__(self, emu: 'Emulator', state):
        self.emu = emu
        self.mu = emu.mu
        self.state: 'BionicTLS' = state
        self.ptr_sz = emu.ptr_size
        
        self.base = 0
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