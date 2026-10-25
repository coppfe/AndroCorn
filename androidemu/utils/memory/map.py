import os
import struct
import unicorn

from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_ERR_MAP

# =========================================================================
# FUTURE DIRECT C-LEVEL OPTIMIZATION STUB
# =========================================================================
# import ctypes
# import unicorn.unicorn as _uc_module
# _uclib = getattr(_uc_module, 'uclib', None) or getattr(_uc_module, '_uc', None)
# if _uclib is None:
#     try:
#         from unicorn.unicorn_py3.unicorn import uclib as _uclib
#     except ImportError:
#         from unicorn.unicorn import _uc as _uclib

from typing import List, Tuple, Dict, Optional, Union, TYPE_CHECKING

from .structs.snapshot import Snapshot
from ...data.layout import STACK_ADDR, PAGE_SIZE, MMAP_BASE
from ..memory.helpers import page_start, page_end, align_up
from ...types import ptr_t

if TYPE_CHECKING:
    import io
    from unicorn import Uc
    from androidemu.kernel.fs.node import VfsNode

_STRUCT_U8  = struct.Struct("<B")
_STRUCT_U16 = struct.Struct("<H")
_STRUCT_U32 = struct.Struct("<I")
_STRUCT_U64 = struct.Struct("<Q")

_PACK_U8  = _STRUCT_U8.pack
_PACK_U16 = _STRUCT_U16.pack
_PACK_U32 = _STRUCT_U32.pack
_PACK_U64 = _STRUCT_U64.pack

_UNPACK_U8  = _STRUCT_U8.unpack_from
_UNPACK_U16 = _STRUCT_U16.unpack_from
_UNPACK_U32 = _STRUCT_U32.unpack_from
_UNPACK_U64 = _STRUCT_U64.unpack_from


class MemoryMap:
    def __init__(self, mu: 'Uc', alloc_min_addr: int, alloc_max_addr: int):
        self._mu: 'Uc' = mu
        self._ptr_sz = ptr_t.size
        
        # self._uch = mu._uch

        # --- Direct C-pointers initialization (archived) ---
        # if self._uch is not None and _uclib is not None:
        #     self._fn_mem_read = getattr(_uclib, 'uc_mem_read', None)
        #     self._fn_mem_write = getattr(_uclib, 'uc_mem_write', None)
        # else:
        #     self._fn_mem_read = None
        #     self._fn_mem_write = None
        # self._buf_8 = (ctypes.c_char * 8)()
        # self._buf_64 = (ctypes.c_char * 64)()

        if self._ptr_sz == 8:
            self.read_ptr = self.read_u64
            self.write_ptr = self.write_u64
        else:
            self.read_ptr = self.read_u32
            self.write_ptr = self.write_u32

        self._alloc_min_addr = alloc_min_addr
        self._alloc_max_addr = alloc_max_addr

        self._brk_ptr = alloc_min_addr
    
        self._file_map_addr: Dict[int, Tuple[int, int, 'VfsNode']] = {}
        self._allocations: Dict[int, int] = {}

        self.map_generation = 0

    def _is_mapped(self, addr: int, size: int) -> bool:
        """Check if the given range is already mapped in Unicorn."""
        try:
            for r_start, r_end, _ in self._mu.mem_regions():
                if max(addr, r_start) < min(addr + size, r_end + 1):
                    return True
            return False
        except Exception:
            return False

    def static_alloc(self, size: int, addr: int = None, align: int = 0x10) -> int:
        if addr is not None:
            target_addr = align_up(addr, align)
        else:
            target_addr = align_up(self._brk_ptr, align)

        end = target_addr + size
        map_start = page_start(target_addr)
        map_end = page_end(end)

        if map_end > self._alloc_max_addr:
            raise RuntimeError(
                f"MemoryMap: Out of address space. Requested end: {map_end:#x}, Max: {self._alloc_max_addr:#x}"
            )

        cur_page = map_start
        while cur_page < map_end:
            if not self._is_mapped(cur_page, PAGE_SIZE):
                try:
                    self._mu.mem_map(cur_page, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE)
                except unicorn.UcError as e:
                    if e.errno != UC_ERR_MAP:
                        raise e
            cur_page += PAGE_SIZE

        if addr is None:
            self._brk_ptr = end
        elif end > self._brk_ptr and target_addr < self._alloc_max_addr:
            if target_addr < self._brk_ptr + STACK_ADDR:
                self._brk_ptr = end

        self._allocations[target_addr] = size
        return target_addr

    def dynamic_alloc(self, n_units: int, is_ptr_array: bool = False) -> int:
        size = n_units * self._ptr_sz if is_ptr_array else n_units
        return self.static_alloc(size)

    def map(self, address: int, size: int, prot: int = UC_PROT_READ | UC_PROT_WRITE,
            node: Optional['VfsNode'] = None, offset: int = 0) -> int:
        if size <= 0:
            raise ValueError("Size must be > 0")

        aligned_size = page_end(size)
        target_addr = self.find_free_region(aligned_size) if address == 0 else address

        try:
            self._mu.mem_map(target_addr, aligned_size, prot)
        except unicorn.UcError as e:
            if e.errno == UC_ERR_MAP:
                self._mu.mem_protect(target_addr, aligned_size, prot)
            else:
                raise e

        if node is not None:
            data = node.read(offset, size)
            if data:
                self.write_bytes(target_addr, data)

            self._file_map_addr[target_addr] = (target_addr + aligned_size, offset, node)

        self._allocations[target_addr] = aligned_size
        self.map_generation += 1

        return target_addr

    def find_free_region(self, size: int, start_search: int = 0) -> int:
        regions = sorted(self._mu.mem_regions())
        search_base = page_end(start_search) if start_search > 0 else MMAP_BASE
        candidate = page_end(search_base)

        for r_start, r_end, _ in regions:
            r_limit = r_end + 1
            if r_start > candidate:
                if (r_start - candidate) >= size:
                    return candidate
            if r_limit > candidate:
                candidate = page_end(r_limit)

        if candidate + size > 0xFFFFFFFF:
            raise RuntimeError(f"MemoryMap: Out of address space. Cannot find {size:#x} bytes.")

        return candidate

    def unmap(self, addr: int, size: int) -> int:
        start = page_start(addr)
        aligned_size = page_end(size)

        try:
            self._mu.mem_unmap(start, aligned_size)
            self._allocations.pop(start, None)
            self._file_map_addr.pop(start, None)
            self.map_generation += 1
            return 0
        except unicorn.UcError:
            return -1

    def protect(self, addr: int, size: int, prot: int) -> int:
        try:
            self._mu.mem_protect(page_start(addr), page_end(size), prot)
            return 0
        except unicorn.UcError:
            return -1

    def _read_fully(self, fd: int, size: int) -> bytes:
        data = b""
        while size > 0:
            chunk = os.read(fd, size)
            if not chunk:
                break
            data += chunk
            size -= len(chunk)
        return data

    def get_regions(self) -> List[Tuple[int, int, int]]:
        return self._mu.mem_regions()

    def dump_maps(self, stream: 'io.StringIO') -> None:
        regions = sorted(self._mu.mem_regions())
        stream.write(f"{'Start':<10} {'End':<10} {'Prot':<5}\n")
        for start, end, prot in regions:
            stream.write(f"{start:08x}-{end+1:08x} {prot:<5}\n")

    def create_snapshot(self) -> 'Snapshot':
        cpu_ctx = self._mu.context_save()
        pages = {}
        for start, end, prot in self._mu.mem_regions():
            if prot & UC_PROT_WRITE:
                size = end - start + 1
                pages[start] = self.read_bytes(start, size)

        return Snapshot(
            cpu_context=cpu_ctx,
            memory_pages=pages,
            brk_ptr=self._brk_ptr,
            generation=self.map_generation
        )

    def restore_snapshot(self, snapshot: 'Snapshot') -> None:
        self._mu.context_restore(snapshot.cpu_context)

        for addr, data in snapshot.memory_pages.items():
            self.write_bytes(addr, data)

        self._brk_ptr = snapshot.brk_ptr
        self.map_generation = snapshot.generation

    @property
    def current_brk(self) -> int:
        return self._brk_ptr

    # =========================================================================
    # PRIMITIVE READERS (Standard Unicorn)
    # =========================================================================

    def read_u8(self, addr: int) -> int:
        # --- Direct C-buffer fast path (archived) ---
        # status = self._fn_mem_read(self._uch, addr, self._buf_8, 1)
        # if status != 0: raise unicorn.UcError(status)
        # return _UNPACK_U8(self._buf_8, 0)[0]
        return _UNPACK_U8(self._mu.mem_read(addr, 1), 0)[0]

    def read_u16(self, addr: int) -> int:
        # --- Direct C-buffer fast path (archived) ---
        # status = self._fn_mem_read(self._uch, addr, self._buf_8, 2)
        # if status != 0: raise unicorn.UcError(status)
        # return _UNPACK_U16(self._buf_8, 0)[0]
        return _UNPACK_U16(self._mu.mem_read(addr, 2), 0)[0]

    def read_u32(self, addr: int) -> int:
        # --- Direct C-buffer fast path (archived) ---
        # status = self._fn_mem_read(self._uch, addr, self._buf_8, 4)
        # if status != 0: raise unicorn.UcError(status)
        # return _UNPACK_U32(self._buf_8, 0)[0]
        return _UNPACK_U32(self._mu.mem_read(addr, 4), 0)[0]

    def read_u64(self, addr: int) -> int:
        # --- Direct C-buffer fast path (archived) ---
        # status = self._fn_mem_read(self._uch, addr, self._buf_8, 8)
        # if status != 0: raise unicorn.UcError(status)
        # return _UNPACK_U64(self._buf_8, 0)[0]
        return _UNPACK_U64(self._mu.mem_read(addr, 8), 0)[0]

    # =========================================================================
    # PRIMITIVE WRITERS (Standard Unicorn)
    # =========================================================================

    def write_u8(self, addr: int, val: int) -> None:
        # --- Direct C-buffer fast path (archived) ---
        # _PACK_U8(self._buf_8, 0, val & 0xFF)
        # status = self._fn_mem_write(self._uch, addr, self._buf_8, 1)
        # if status != 0: raise unicorn.UcError(status)
        self._mu.mem_write(addr, _PACK_U8(val & 0xFF))

    def write_u16(self, addr: int, val: int) -> None:
        # --- Direct C-buffer fast path (archived) ---
        # _PACK_U16(self._buf_8, 0, val & 0xFFFF)
        # status = self._fn_mem_write(self._uch, addr, self._buf_8, 2)
        # if status != 0: raise unicorn.UcError(status)
        self._mu.mem_write(addr, _PACK_U16(val & 0xFFFF))

    def write_u32(self, addr: int, val: int) -> None:
        # --- Direct C-buffer fast path (archived) ---
        # _PACK_U32(self._buf_8, 0, val & 0xFFFFFFFF)
        # status = self._fn_mem_write(self._uch, addr, self._buf_8, 4)
        # if status != 0: raise unicorn.UcError(status)
        self._mu.mem_write(addr, _PACK_U32(val & 0xFFFFFFFF))

    def write_u64(self, addr: int, val: int) -> None:
        # --- Direct C-buffer fast path (archived) ---
        # _PACK_U64(self._buf_8, 0, val & 0xFFFFFFFFFFFFFFFF)
        # status = self._fn_mem_write(self._uch, addr, self._buf_8, 8)
        # if status != 0: raise unicorn.UcError(status)
        self._mu.mem_write(addr, _PACK_U64(val & 0xFFFFFFFFFFFFFFFF))

    # =========================================================================
    # BUFFER & STRING READ / WRITE
    # =========================================================================

    def read_bytes(self, addr: int, size: int) -> bytes:
        if size <= 0:
            return b""
        # --- Direct C-buffer fast path (archived) ---
        # buf = (ctypes.c_char * size)()
        # status = self._fn_mem_read(self._uch, addr, buf, size)
        # if status != 0: raise unicorn.UcError(status)
        # return buf.raw
        return bytes(self._mu.mem_read(addr, size))

    def read_into(self, addr: int, target: Union[bytearray, memoryview], size: Optional[int] = None) -> int:
        read_sz = len(target) if size is None else size
        if read_sz <= 0:
            return 0
        # --- Direct C-buffer fast path (archived) ---
        # c_buf = (ctypes.c_char * read_sz).from_buffer(target)
        # status = self._fn_mem_read(self._uch, addr, c_buf, read_sz)
        # if status != 0: raise unicorn.UcError(status)
        # return read_sz
        data = self._mu.mem_read(addr, read_sz)
        target[:read_sz] = data
        return read_sz

    def write_bytes(self, addr: int, data: Union[bytes, bytearray, memoryview]) -> None:
        sz = len(data)
        if sz <= 0:
            return

        # --- Direct C-buffer fast path (archived) ---
        # if isinstance(data, bytes):
        #     status = self._fn_mem_write(self._uch, addr, data, sz)
        # elif isinstance(data, bytearray):
        #     c_buf = (ctypes.c_char * sz).from_buffer(data)
        #     status = self._fn_mem_write(self._uch, addr, c_buf, sz)
        # else:
        #     raw_bytes = data.tobytes() if isinstance(data, memoryview) else bytes(data)
        #     status = self._fn_mem_write(self._uch, addr, raw_bytes, sz)
        # if status != 0: raise unicorn.UcError(status)

        if isinstance(data, bytes):
            payload = data
        elif isinstance(data, bytearray):
            payload = bytes(data)
        elif isinstance(data, memoryview):
            payload = data.tobytes()
        else:
            payload = bytes(data)

        sz = len(payload)
        self._mu.mem_write(addr, payload)