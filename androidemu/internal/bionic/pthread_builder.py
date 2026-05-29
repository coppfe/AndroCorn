import logging
from abc import ABC, abstractmethod

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.utils.memory.map import MemoryMap


logger = logging.getLogger(__name__)

class PThreadBuilder(ABC):
    def __init__(self, memory: 'MemoryMap'):
        self.memory = memory

    @abstractmethod
    def build(self) -> int:
        raise NotImplementedError()