from abc import ABC, abstractmethod

from ...config import TLS_BASE

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator
    from .dtv_builder import DTVBuilder
    from .pthread_builder import PThreadBuilder

class BionicTLS(ABC):
    def __init__(self, emu: 'Emulator'):
        self.emu = emu
        self.mu = emu.mu
        self.ptr_sz = self.emu.get_ptr_size()
        
        self.counter_memory = TLS_BASE

        self.tp = 0
        self.dtv = 0
        self.pthread_internal = 0
        self.kernel_args_base = 0
        self.errno_ptr = 0

        self.dtv_builder: 'DTVBuilder' = None
        self.pthread_builder: 'PThreadBuilder' = None

    @abstractmethod
    def setup_static_tls(self, reader, bias):
        raise NotImplementedError

    @abstractmethod
    def bootstrap(self, phdr_addr, phnum, entry_point):
        raise NotImplementedError

    @abstractmethod
    def mem_reserve(self, size: int, align: int = 0x10) -> int:
        raise NotImplementedError