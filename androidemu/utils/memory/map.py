import os
import unicorn

from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_ERR_MAP

from typing import List, Tuple, Dict, Optional, TYPE_CHECKING

from .structs.snapshot import Snapshot

from ...data.layout import STACK_ADDR, PAGE_SIZE, MMAP_BASE

from ..memory.helpers import page_start, page_end, align_up

from ...types import ptr_t

if TYPE_CHECKING:
    import io
    from unicorn import Uc

    from androidemu.kernel.fs.node import VfsNode

class MemoryMap:
    def __init__(self, mu: 'Uc', alloc_min_addr: int, alloc_max_addr: int):
        self._mu: 'Uc' = mu
        self._ptr_sz = ptr_t.size

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
        except:
            return False

    def static_alloc(self, size: int, addr: int = None, align: int = 0x10) -> int:
        """
        Allocate memory.
        If addr is provided, it acts as a fixed-base mapping (for TLS/Soinfo zones).
        If addr is None, it acts as a linear allocator (for general heap).
        """
        if addr is not None:
            target_addr = align_up(addr, align)
        else:
            target_addr = align_up(self._brk_ptr, align)

        end = target_addr + size
        map_start = page_start(target_addr)
        map_end = page_end(end)

        if map_end > self._alloc_max_addr:
            raise RuntimeError(f"MemoryMap: Out of address space. Requested end: {map_end:#x}, Max: {self._alloc_max_addr:#x}")

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
        """
        Fast allocation for dynamic data or arrays of pointers.

        :param n_units: Number of bytes or number of pointers.
        :param is_ptr_array: If True, n_units is treated as count of pointers (size * ptr_sz).
        :return: Allocated address.
        """
        size = n_units * self._ptr_sz if is_ptr_array else n_units
        return self.static_alloc(size)

    def map(self, address: int, size: int, prot: int = UC_PROT_READ | UC_PROT_WRITE,
            node: Optional['VfsNode'] = None, offset: int = 0) -> int:
        """
        Standard memory mapping (page-aligned).
        If address is 0, finds a free region automatically.

        :param address: Target address (must be page aligned if not 0).
        :param size: Size in bytes.
        :param prot: Protection flags (UC_PROT_...).
        :param node: Optional VfsNode to load data from.
        :param offset: File offset.
        :return: Base address of the mapped region.
        """
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
                self._mu.mem_write(target_addr, data)

            self._file_map_addr[target_addr] = (target_addr + aligned_size, offset, node)

        self._allocations[target_addr] = aligned_size
        self.map_generation += 1

        return target_addr

    def find_free_region(self, size: int, start_search: int = 0) -> int:
        """
        Finds a continuous unmapped memory region.
        """
        regions = sorted(self._mu.mem_regions())

        if start_search > 0:
            search_base = page_end(start_search)
        else:
            search_base = MMAP_BASE
            
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
        """Unmap a memory region and clean up tracking."""
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
        """Change memory protection."""
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
        """Return list of all mapped regions (start, end, prot)."""
        return self._mu.mem_regions()

    def dump_maps(self, stream: 'io.StringIO') -> None:
        """Write current memory map to a stream."""
        regions = sorted(self._mu.mem_regions())
        stream.write(f"{'Start':<10} {'End':<10} {'Prot':<5}\n")
        for start, end, prot in regions:
            stream.write(f"{start:08x}-{end+1:08x} {prot:<5}\n")

    def create_snapshot(self) -> 'Snapshot':
        """
        Takes a full snapshot of CPU registers and writable (RW) memory regions.
        Ignores Read-Only/Execute code segments to save memory and time.
        """
        cpu_ctx = self._mu.context_save()

        pages = {}
        for start, end, prot in self._mu.mem_regions():
            if prot & UC_PROT_WRITE:
                size = end - start + 1
                pages[start] = self._mu.mem_read(start, size)

        return Snapshot(
            cpu_context=cpu_ctx,
            memory_pages=pages,
            brk_ptr=self._brk_ptr,
            generation=self.map_generation
        )

    def restore_snapshot(self, snapshot: 'Snapshot') -> None:
        """
        Restores CPU state and rolls back all writable memory pages to the snapshot.
        """
        self._mu.context_restore(snapshot.cpu_context)

        for addr, data in snapshot.memory_pages.items():
            self._mu.mem_write(addr, data)

        self._brk_ptr = snapshot.brk_ptr
        self.map_generation = snapshot.generation

    @property
    def current_brk(self) -> int:
        """Get the current counter-allocation pointer."""
        return self._brk_ptr
