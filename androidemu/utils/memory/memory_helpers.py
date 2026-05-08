import struct
import logging

from unicorn import *
from unicorn.arm_const import *

logger = logging.getLogger(__name__)

def read_ptr_sz(mu, address: int, sz: int) -> int:
    """
    Read a pointer from memory.

    :param address: The address of the pointer
    :param sz: The size of the pointer

    :return: The pointer
    """
    return int.from_bytes(mu.mem_read(address, sz), byteorder='little')

def read_byte_array(mu, address: int, size: int) -> bytearray:
    """
    Read a byte array from memory.

    :param address: The address of the byte array
    :param size: The size of the byte array

    :return: The byte array
    """
    return mu.mem_read(address, size)

def read_utf8(mu, address: int) -> str:
    """
    Read a string from memory.

    :param address: The address of the string

    :return: The string
    """
    buffer_address = address
    buffer_read_size = 32
    buffer = b""
    null_pos = None
    while null_pos is None:
        buf_read = mu.mem_read(buffer_address, buffer_read_size)
        if b'\x00' in buf_read:
            null_pos = len(buffer) + buf_read.index(b'\x00')
        buffer += buf_read
        buffer_address += buffer_read_size

    return buffer[:null_pos].decode("utf-8")

def read_uints(mu, address, num=1) -> list:
    data = mu.mem_read(address, num * 4)
    return struct.unpack("I" * num, data)


def write_utf8(mu, address: int, value: int) -> int:
    """
    Write a string to memory.

    :param address: The address of the string
    :param value: The string

    :return: The length of the string
    """
    value_utf8 = value.encode(encoding="utf-8")
    mu.mem_write(address, value_utf8 + b"\x00")
    return len(value_utf8)+1


def write_uints(mu, address: int, num: int) -> None:
    """
    Write an unsigned integer to memory.

    :param address: The address of the integer
    :param num: The integer
    """
    #FIXME 写死了ptr大小，需要换成write_ptrs_sz
    l = []
    if not isinstance(num, list):
        l = [num]
    else:
        l = num

    for v in l:
        mu.mem_write(address, int(v).to_bytes(4, byteorder='little'))
        address += 4
    #
#

def write_ptrs_sz(mu, address: int, num: int, ptr_sz: int) -> None:
    """
    Write a pointer to memory.

    :param address: The address of the pointer
    :param num: The pointer

    :return: The length of the pointer
    """
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
    #
    return n
#