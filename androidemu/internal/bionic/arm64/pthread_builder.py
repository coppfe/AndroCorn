from ..pthread_builder import PThreadBuilder

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.utils.memory.map import MemoryMap

class PThreadBuilderARM64(PThreadBuilder):

    def __init__(self, memory: 'MemoryMap'):
        super().__init__(memory)

    def build(self) -> int:
        # libc will fill struct pthread
        size = 0x400
        base = self.memory.static_alloc(size, align=0x10)

        return base