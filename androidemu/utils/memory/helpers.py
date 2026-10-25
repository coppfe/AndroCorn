import os
from typing import List, Union, TYPE_CHECKING
from ...data.layout import PAGE_SIZE

if TYPE_CHECKING:
    from .map import MemoryMap
    from ...core.emulator import Emulator

def read_ptr_sz(mem: 'MemoryMap', address: int) -> int:
    return mem.read_ptr(address)

def read_ptr_array(mem: 'MemoryMap', address: int, size: int) -> List[int]:
    ptr_sz = mem._ptr_sz
    invalid = (1 << (ptr_sz * 8)) - 1
    addrs = []
    curr = address

    for _ in range(size // ptr_sz):
        v = mem.read_ptr(curr)
        if v != 0 and v != invalid:
            addrs.append(v)
        curr += ptr_sz

    return addrs


def read_byte_array(mem: 'MemoryMap', address: int, size: int) -> bytearray:
    buf = bytearray(size)
    mem.read_into(address, buf, size)
    return buf

def read_utf8(mem: 'MemoryMap', address: int) -> str:
    chars = bytearray()
    curr = address

    while True:
        val = mem.read_u32(curr)

        b0 = val & 0xFF
        if not b0:
            break
        chars.append(b0)

        b1 = (val >> 8) & 0xFF
        if not b1:
            break
        chars.append(b1)

        b2 = (val >> 16) & 0xFF
        if not b2:
            break
        chars.append(b2)

        b3 = (val >> 24) & 0xFF
        if not b3:
            break
        chars.append(b3)

        curr += 4

    return chars.decode('utf-8', errors='ignore')


def read_uints(mem: 'MemoryMap', address: int, num: int = 1) -> List[int]:
    return [mem.read_u32(address + (i * 4)) for i in range(num)]


def write_utf8(mem: 'MemoryMap', address: int, value: str) -> int:
    raw = value.encode('utf-8') + b'\x00'
    size = len(raw)
    curr = address
    off = 0

    while off + 8 <= size:
        mem.write_u64(curr, int.from_bytes(raw[off:off + 8], 'little'))
        curr += 8
        off += 8

    if off + 4 <= size:
        mem.write_u32(curr, int.from_bytes(raw[off:off + 4], 'little'))
        curr += 4
        off += 4

    if off + 2 <= size:
        mem.write_u16(curr, int.from_bytes(raw[off:off + 2], 'little'))
        curr += 2
        off += 2

    if off < size:
        mem.write_u8(curr, raw[off])

    return size


def write_uints(mem: 'MemoryMap', address: int, num: Union[int, List[int]]) -> int:
    ptr_sz = mem._ptr_sz
    if isinstance(num, int):
        mem.write_ptr(address, num)
        return ptr_sz

    curr = address
    for v in num:
        mem.write_ptr(curr, v)
        curr += ptr_sz

    return curr - address

def hexdump(mem: 'MemoryMap', address: int, size: int = 64) -> str:
    data = read_byte_array(mem, address, size)
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{address + i:08x}:  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)


def telescope(emu: 'Emulator', address: int, depth: int = 5) -> str:
    lines = []
    mem = emu.memory
    ptr_sz = mem._ptr_sz
    curr_addr = address

    for _ in range(depth):
        try:
            val = mem.read_ptr(curr_addr)
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
                deref = mem.read_ptr(target)
                chain.append(f"-> {deref:08x}{mod_info}")
                target = deref
            except Exception:
                try:
                    s = read_utf8(mem, target)
                    if s and len(s) >= 3 and s.isprintable():
                        chain.append(f'-> "{s}"{mod_info}')
                except Exception:
                    pass
                break

        lines.append(" ".join(chain))
        curr_addr += ptr_sz

    return "\n".join(lines)


def read_string_auto(mem: 'MemoryMap', address: int, max_len: int = 256) -> str:
    raw = read_byte_array(mem, address, max_len)
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
        try:
            null_term = raw.find(b"\x00\x00")
            if null_term != -1:
                return raw[:null_term + (null_term % 2)].decode("utf-16le", errors="ignore")
            return raw.decode("utf-16le", errors="ignore")
        except Exception:
            pass
    return read_utf8(mem, address)


def find_bytes(mem: 'MemoryMap', pattern: bytes, start: int, end: int) -> List[int]:
    chunk_size = 0x10000
    results = []
    curr = start

    while curr < end:
        to_read = min(chunk_size, end - curr)
        try:
            buf = read_byte_array(mem, curr, to_read)
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

def page_start(addr: int) -> int:
    return addr & (~(PAGE_SIZE - 1))


def page_end(addr: int) -> int:
    return page_start(addr + (PAGE_SIZE - 1))


def normalize_dirfd(dirfd: int) -> int:
    if dirfd & 0x80000000:
        return dirfd - 0x100000000
    return dirfd


def align_up(value: int, p: int = PAGE_SIZE) -> int:
    if p == 0:
        return value
    return (value + p - 1) & ~(p - 1)


def align_down(x: int, p: int = PAGE_SIZE) -> int:
    return x & ~(p - 1)


def is_thumb(cpsr: int) -> bool:
    return (cpsr & (1 << 5)) != 0


def standlize_addr(addr: int) -> int:
    return addr & (~1)