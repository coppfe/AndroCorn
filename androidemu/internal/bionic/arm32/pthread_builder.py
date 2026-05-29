from ..pthread_builder import PThreadBuilder

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.utils.memory.map import MemoryMap


class PThreadBuilderARM32(PThreadBuilder):
    def __init__(self, memory: 'MemoryMap'):
        super().__init__(memory)

    def build(self) -> int:
        size = 0x400 
        base = self.memory.static_alloc(size, align=0x10)

        return base