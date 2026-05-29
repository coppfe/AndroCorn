from . import helpers

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from unicorn import Uc
    from androidemu.utils.memory.map import MemoryMap

class StructWriter:
    def __init__(self, mu: 'Uc', memory: 'MemoryMap'):
        self._mu = mu
        self._memory = memory

    def write_val(self, value: int) -> int:
        """
        Write a value to memory.

        :param value: The value

        :return: The address of the value
        """
        addr = self._memory.dynamic_alloc(1)
        helpers.write_uints(self._mu, addr, value)
        return addr

    def write_utf8(self, str_val: str) -> int:
        """
        Write a string to memory.

        :param str_val: The string

        :return: The length of the string
        """
        value_utf8 = str_val.encode(encoding="utf-8") + b"\x00"
        n = len(value_utf8)
        addr = self._memory.dynamic_alloc(n, is_ptr_array=True)
        self._mu.mem_write(addr, value_utf8)
        return addr