from unicorn.arm_const import *
from unicorn.arm64_const import *
from . import memory_helpers

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator

class StructWriter:
    def __init__(self, emu: 'Emulator', base_addr):
        self.__emu = emu
        self.__base = base_addr
        self.__current = base_addr
        self.__ptr_sz = emu.ptr_size

    def reserve(self, nptr):
        addr = self.__current
        self.__current += nptr * self.__ptr_sz
        return addr

    def reserve_bytes(self, nbytes):
        addr = self.__current
        self.__current += nbytes
        return addr

    def write_val(self, value):
        addr = self.reserve(1)
        memory_helpers.write_ptrs_sz(self.__emu.mu, addr, value, self.__ptr_sz)
        return addr

    def write_utf8(self, str_val):
        value_utf8 = str_val.encode(encoding="utf-8") + b"\x00"
        n = len(value_utf8)
        addr = self.reserve_bytes(n)
        self.__emu.mu.mem_write(addr, value_utf8)
        return addr

    def current_addr(self):
        return self.__current