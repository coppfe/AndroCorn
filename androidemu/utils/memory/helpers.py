import struct

from typing import List

from ...types import ptr_t

from ...data.mem_map import PAGE_SIZE
from ...const.linux import *

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from unicorn import Uc

def read_ptr_sz(mu: 'Uc', address: int) -> int:
    """
    Read a pointer from memory.

    :param address: The address of the pointer

    :return: The pointer
    """
    return int.from_bytes(mu.mem_read(address, ptr_t.size), byteorder='little')

def read_byte_array(mu: 'Uc', address: int, size: int) -> bytearray:
    """
    Read a byte array from memory.

    :param address: The address of the byte array
    :param size: The size of the byte array

    :return: The byte array
    """
    return mu.mem_read(address, size)

def read_utf8(mu: 'Uc', address: int) -> str:
    chunk = mu.mem_read(address, 256)
    try:
        null_pos = chunk.index(b'\x00')
        return chunk[:null_pos].decode("utf-8")
    except ValueError:
        pass

    buffer = bytearray(chunk)
    buffer_address = address + 256
    
    while True:
        buf_read = mu.mem_read(buffer_address, 64)
        try:
            null_pos = buf_read.index(b'\x00')
            buffer.extend(buf_read[:null_pos])
            break
        except ValueError:
            buffer.extend(buf_read)
            buffer_address += 64

    return buffer.decode("utf-8", errors='ignore')

def read_uints(mu: 'Uc', address, num=1) -> list:
    data = mu.mem_read(address, num * 4)
    return struct.unpack("I" * num, data)


def write_utf8(mu: 'Uc', address: int, value: int) -> int:
    """
    Write a string to memory.

    :param address: The address of the string
    :param value: The string

    :return: The length of the string
    """
    value_utf8 = value.encode(encoding="utf-8")
    mu.mem_write(address, value_utf8 + b"\x00")
    return len(value_utf8)+1


def write_uints(mu: 'Uc', address: int, num: List[int]) -> None:
    """
    Write a pointer to memory.

    :param address: The address of the pointer
    :param num: The pointer

    :return: The length of the pointer
    """
    ptr_sz = ptr_t.size
    l = []
    if not isinstance(num, list):
        l = [num]
    else:
        l = num
    n = 0
    for v in l:
        mu.mem_write(address, int(v).to_bytes(ptr_sz, byteorder='little'))
        address += ptr_sz
        n += ptr_sz
    return n


def page_start(addr: int):
    return addr & (~(PAGE_SIZE-1))

def page_end(addr: int):
    return page_start(addr+(PAGE_SIZE-1))

# def get_segment_protection(prot_in: int):
#     prot = 0

#     if prot_in & PF_R != 0:
#         prot |= 1

#     if prot_in & PF_W != 0:
#         prot |= 2

#     if prot_in & PF_X != 0:
#         prot |= 4

#     return prot