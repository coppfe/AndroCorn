import struct
import logging

from unicorn import *
from unicorn.arm_const import *

logger = logging.getLogger(__name__)

def read_ptr_sz(mu, address, sz) -> int:
    return int.from_bytes(mu.mem_read(address, sz), byteorder='little')

def read_ptr(mu, address) -> int:
    #FIXME The ptr size is hardcoded, so all calls to this function must be changed to read_ptr_sz.
    return int.from_bytes(mu.mem_read(address, 4), byteorder='little')
#


def read_byte_array(mu, address, size) -> bytearray:
    return mu.mem_read(address, size)


def read_utf8(mu, address) -> str:
    buffer_address = address
    buffer_read_size = 32
    buffer = b""
    null_pos = None
    # FIXME has an out-of-bounds read issue, which likely has a bug and needs to be fixed.
    # Keep reading until we read something that contains a null terminator.
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


def write_utf8(mu, address, value):
    value_utf8 = value.encode(encoding="utf-8")
    mu.mem_write(address, value_utf8 + b"\x00")
    return len(value_utf8)+1
#


def write_uints(mu, address, num) -> None:
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

def write_ptrs_sz(mu, address, num, ptr_sz) -> None:
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

def mem_reserve(mu: 'Uc', start: int, end: int, page_size: int) -> int:

        addr_start = start & ~(page_size - 1)
        addr_end = (end + page_size - 1) & ~(page_size - 1)
        size = addr_end - addr_start

        try:
            mu.mem_map(addr_start, size, UC_PROT_ALL)
            logger.debug("[+] mem_map success: %#x - %#x (size: %#x)", addr_start, addr_end, size)

        except UcError as e:
            logger.warning("[!] Region %#x already mapped, protecting...", addr_start)
            mu.mem_protect(addr_start, size, UC_PROT_ALL)

        return addr_start