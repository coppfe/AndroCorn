from ..pthread_builder import PThreadBuilder

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ....emulator import Emulator

class PThreadBuilderARM64(PThreadBuilder):

    def __init__(self, emu: 'Emulator'):
        super().__init__(emu)

    def build(self) -> int:
        # libc will fill struct pthread
        size = 0x400
        base = self.emu.memory.static_alloc(size, align=0x10)

        return base