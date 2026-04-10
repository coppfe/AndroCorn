from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..emulator import Emulator

class LibC:
    def __init__(self, emu: 'Emulator'):
        self.__emu: 'Emulator' = emu

        self.libc = emu.get_library('libc.so')

    def malloc(self, size):
        # ptr = self.__emu.call_symbol(self.libc, 'malloc', size)
        # if ptr == 0:
        #     raise MemoryError(f"Native malloc failed to allocate {size} bytes")
        # return ptr
        return self.__emu.memory.map(0, size)
    
    def free(self, ptr):
        # return self.__emu.call_symbol(self.libc, 'free', ptr)
        pass