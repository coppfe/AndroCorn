import logging
from abc import ABC, abstractmethod

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator
    from .tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class PThreadBuilder(ABC):
    def __init__(self, emu: 'Emulator'):
        self.emu = emu

    @abstractmethod
    def build(self) -> int:
        raise NotImplementedError()