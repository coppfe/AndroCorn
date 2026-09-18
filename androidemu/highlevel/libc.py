from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..core.emulator import Emulator

# it's a system class that used by JNI
# if you sure your app isn't use JNI (probably JNI using by any app) - you can load emulator without initing sys libs

class LibC:
    def __init__(self, emu: 'Emulator'):
        self._emu: 'Emulator' = emu
        self._libc_cache = None

    @property
    def libc(self):
        if self._libc_cache is None:
            self._libc_cache = self._emu.get_library('libc.so')
            if self._libc_cache is None:
                raise RuntimeError("Cannot resolve libc.so. Is libraries initialized? Load libc before calling native methods.")
        return self._libc_cache

    def malloc(self, size: int) -> int:
        ptr = self._emu.call_symbol(self.libc, 'malloc', size)
        if ptr == 0:
            raise MemoryError(f"Native malloc failed to allocate {size} bytes")
        return ptr
    
    def free(self, ptr: int):
        if ptr != 0:
            self._emu.call_symbol(self.libc, 'free', ptr)