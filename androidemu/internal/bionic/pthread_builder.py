from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.utils.memory.map import MemoryMap


class PThreadBuilder:
    def __init__(self, memory: 'MemoryMap'):
        self.memory = memory

    def build(self) -> int:
        size = 0x400 
        base = self.memory.static_alloc(size, align=0x10)

        return base