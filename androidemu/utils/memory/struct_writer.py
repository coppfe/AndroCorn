from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.utils.memory.map import MemoryMap


class StructWriter:
    def __init__(self, memory: 'MemoryMap'):
        self._memory = memory

    def write_val(self, value: int) -> int:
        """
        Allocate memory for a pointer/value and write it.

        :param value: The value/pointer to write
        :return: Allocated memory address
        """
        addr = self._memory.dynamic_alloc(1, is_ptr_array=True)
        self._memory.write_ptr(addr, value)
        return addr

    def write_utf8(self, str_val: str) -> int:
        """
        Allocate memory for a null-terminated UTF-8 string and write it.

        :param str_val: The string
        :return: Allocated memory address
        """
        raw = str_val.encode("utf-8") + b"\x00"
        addr = self._memory.dynamic_alloc(len(raw), is_ptr_array=False)
        self._memory.write_bytes(addr, raw)
        return addr