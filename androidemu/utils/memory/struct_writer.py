from unicorn.arm_const import *
from unicorn.arm64_const import *
from . import memory_helpers

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator

class StructWriter:
    def __init__(self, emu: 'Emulator'):
        self.__emu = emu
        self.__ptr_sz = emu.ptr_size

    def write_val(self, value: int) -> int:
        """
        Write a value to memory.

        :param value: The value

        :return: The address of the value
        """
        addr = self.__emu.memory.dynamic_alloc(1)
        memory_helpers.write_ptrs_sz(self.__emu.mu, addr, value, self.__ptr_sz)
        return addr

    def write_utf8(self, str_val: str) -> int:
        """
        Write a string to memory.

        :param str_val: The string

        :return: The length of the string
        """
        value_utf8 = str_val.encode(encoding="utf-8") + b"\x00"
        n = len(value_utf8)
        addr = self.__emu.memory.dynamic_alloc(n, is_ptr_array=True)
        self.__emu.mu.mem_write(addr, value_utf8)
        return addr