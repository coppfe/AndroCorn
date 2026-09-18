import struct
import os

from typing import List, TYPE_CHECKING

from ...types import ptr_t

from ...data.layout import PAGE_SIZE
from ...const.linux import *

if TYPE_CHECKING:
    from androidemu import Emulator

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

def read_ptr_array(mu:'Uc', address: int, size: int) -> List[int]:
    """
    Read array of pointers from memory.

    :param address: Source
    :param size: Array Size
    """
    ptr_sz = ptr_t.size
    count = size // ptr_sz
    raw_data = mu.mem_read(address, size)
    
    invalid_marker = (1 << (ptr_sz * 8)) - 1
    addrs = []

    for i in range(count):
        val = int.from_bytes(raw_data[i * ptr_sz : (i + 1) * ptr_sz], 'little')
        if val not in (0, invalid_marker):
            addrs.append(val)

    return addrs

def read_byte_array(mu: 'Uc', address: int, size: int) -> bytearray:
    """
    Read a byte array from memory.

    :param address: The address of the byte array
    :param size: The size of the byte array

    :return: The byte array
    """
    return mu.mem_read(address, size)

def read_utf8(mu: 'Uc', address: int) -> str:
    """
    Read strings from memory

    :param address: Source
    """
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

def read_uints(mu: 'Uc', address: int, num: int = 1) -> list:
    """
    Read list of uints from memory.
    
    :param address: Source
    :param num: How many
    """
    data = mu.mem_read(address, num * 4)
    return struct.unpack("I" * num, data)


def write_utf8(mu: 'Uc', address: int, value: str) -> int:
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

def hexdump(mu: 'Uc', address: int, size: int = 64) -> str:
    """
    Returns formatted hex dump of memory (address, hex bytes, ascii).
    """
    data = mu.mem_read(address, size)
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{address + i:08x}:  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)


def telescope(emu: 'Emulator', address: int, depth: int = 5) -> str:
    """
    Dereferences pointer chains recursively (similar to GEF/pwndbg telescope).
    Useful for inspecting the stack and structures.
    """
    lines = []
    ptr_sz = ptr_t.size
    curr_addr = address
    mu = emu.mu

    for i in range(depth):
        try:
            val = read_ptr_sz(mu, curr_addr)
        except Exception:
            break

        chain = [f"{curr_addr:08x}: {val:08x}"]
        target = val
        for _ in range(3):
            mod_info = ""
            for mod in emu.linker.modules:
                if mod.base <= target < mod.base + mod.size:
                    mod_info = f" ({os.path.basename(mod.filename)}+{target - mod.base:#x})"
                    break

            try:
                deref = read_ptr_sz(mu, target)
                chain.append(f"-> {deref:08x}{mod_info}")
                target = deref
            except Exception:
                try:
                    s = read_utf8(mu, target)
                    if s and len(s) >= 3 and s.isprintable():
                        chain.append(f'-> "{s}"{mod_info}')
                except Exception:
                    pass
                break

        lines.append(" ".join(chain))
        curr_addr += ptr_sz

    return "\n".join(lines)


def read_string_auto(mu: 'Uc', address: int, max_len: int = 256) -> str:
    """
    Automatically detects whether string is UTF-16LE or UTF-8 and decodes it.
    """
    raw = mu.mem_read(address, max_len)
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
        try:
            null_term = raw.find(b"\x00\x00")
            if null_term != -1:
                return raw[:null_term + (null_term % 2)].decode("utf-16le", errors="ignore")
            return raw.decode("utf-16le", errors="ignore")
        except Exception:
            pass
    return read_utf8(mu, address)


def find_bytes(mu: 'Uc', pattern: bytes, start: int, end: int) -> List[int]:
    """
    Scans memory range for a byte pattern.
    """
    chunk_size = 0x10000
    results = []
    curr = start

    while curr < end:
        to_read = min(chunk_size, end - curr)
        try:
            buf = mu.mem_read(curr, to_read)
            idx = 0
            while True:
                pos = buf.find(pattern, idx)
                if pos == -1:
                    break
                results.append(curr + pos)
                idx = pos + 1
        except Exception:
            pass
        curr += to_read

    return results

def page_start(addr: int):
    return addr & (~(PAGE_SIZE-1))

def page_end(addr: int):
    return page_start(addr+(PAGE_SIZE-1))

def normalize_dirfd(dirfd: int) -> int:
    """
    Sign-extends 32-bit unsigned dirfd representation (e.g. 0xFFFFFF9C) 
    back to a signed Python int (-100 for AT_FDCWD).
    """
    if dirfd & 0x80000000:
        return dirfd - 0x100000000
    return dirfd

def align_up(value: int, p: int = PAGE_SIZE) -> int:
    if p == 0:
        return value
    return (value + p - 1) & ~(p - 1)

def align_down(x: int, p: int = PAGE_SIZE) -> int:
    return x & ~(p - 1)

def is_thumb(cpsr):
    return (cpsr & (1<<5)) != 0

def standlize_addr(addr):
    return addr & (~1)

# def get_segment_protection(prot_in: int):
#     prot = 0

#     if prot_in & PF_R != 0:
#         prot |= 1

#     if prot_in & PF_W != 0:
#         prot |= 2

#     if prot_in & PF_X != 0:
#         prot |= 4

#     return prot