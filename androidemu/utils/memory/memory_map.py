import os
import unicorn
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_ERR_MAP
from typing import List, Tuple, Dict, TYPE_CHECKING

from ...data.mem_map import PAGE_SIZE, STACK_ADDR

from ..misc_utils import page_start, page_end

if TYPE_CHECKING:
    import io
    from unicorn import Uc
    from ...objects.virtual_file import VirtualFile

class MemoryMap:
    def __init__(self, mu: 'Uc', alloc_min_addr: int, alloc_max_addr: int, ptr_sz: int):
        self.__mu: 'Uc' = mu
        self.__ptr_sz = ptr_sz
        
        self._alloc_min_addr = alloc_min_addr
        self._alloc_max_addr = alloc_max_addr

        self._brk_ptr = alloc_min_addr

        self.__file_map_addr: Dict[int, Tuple[int, int, 'VirtualFile']] = {}
        self.__allocations: Dict[int, int] = {}

    @staticmethod
    def _align_up(value: int, align: int) -> int:
        if align == 0:
            return value
        return (value + align - 1) & ~(align - 1)

    def _is_mapped(self, addr: int, size: int) -> bool:
        """Check if the given range is already mapped in Unicorn."""
        try:
            for r_start, r_end, _ in self.__mu.mem_regions():
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

        :param size: Size in bytes.
        :param addr: Fixed base address.
        :param align: Alignment in bytes.
        :return: Base address of the allocated region.
        """
        if addr is not None:
            target_addr = self._align_up(addr, align)
        else:
            target_addr = self._align_up(self._brk_ptr, align)

        end = target_addr + size
        map_start = page_start(target_addr)
        map_end = page_end(end)
        
        if map_end > self._alloc_max_addr:
            raise RuntimeError(f"MemoryMap: Out of address space. Requested end: {map_end:#x}, Max: {self._alloc_max_addr:#x}")

        map_size = map_end - map_start
        if not self._is_mapped(map_start, map_size):
            try:
                self.__mu.mem_map(map_start, map_size, UC_PROT_READ | UC_PROT_WRITE)
            except unicorn.UcError as e:
                if e.errno != UC_ERR_MAP:
                    raise e

        if addr is None:
            self._brk_ptr = end
        elif end > self._brk_ptr and target_addr < self._alloc_max_addr:
            if target_addr < self._brk_ptr + STACK_ADDR:
                self._brk_ptr = end

        self.__allocations[target_addr] = size
        return target_addr

    def dynamic_alloc(self, n_units: int, is_ptr_array: bool = False) -> int:
        """
        Fast allocation for dynamic data or arrays of pointers.

        :param n_units: Number of bytes or number of pointers.
        :param is_ptr_array: If True, n_units is treated as count of pointers (size * ptr_sz).
        :return: Allocated address.
        """
        size = n_units * self.__ptr_sz if is_ptr_array else n_units
        return self.static_alloc(size)

    def map(self, address: int, size: int, prot: int = UC_PROT_READ | UC_PROT_WRITE, 
             vf: 'VirtualFile' = None, offset: int = 0) -> int:
        """
        Standard memory mapping (page-aligned). 
        If address is 0, finds a free region automatically.

        :param address: Target address (must be page aligned if not 0).
        :param size: Size in bytes.
        :param prot: Protection flags (UC_PROT_...).
        :param vf: Optional VirtualFile to load data from.
        :param offset: File offset.
        :return: Base address of the mapped region.
        """
        if size <= 0:
            raise ValueError("Size must be > 0")

        aligned_size = page_end(size)
        
        if address == 0:
            target_addr = self.find_free_region(aligned_size)
        else:
            if address % PAGE_SIZE != 0:
                raise RuntimeError(f"Address {address:#x} is not page aligned")
            target_addr = address

        if target_addr + aligned_size > self._alloc_max_addr:
            pass 

        try:
            self.__mu.mem_map(target_addr, aligned_size, prot)
        except unicorn.UcError as e:
            if e.errno == UC_ERR_MAP:
                self.__mu.mem_protect(target_addr, aligned_size, prot)
            else:
                raise e

        if vf is not None:
            original_off = os.lseek(vf.descriptor, 0, os.SEEK_CUR)
            os.lseek(vf.descriptor, offset, os.SEEK_SET)
            
            data = self.__read_fully(vf.descriptor, size)
            if data:
                self.__mu.mem_write(target_addr, data)
            
            self.__file_map_addr[target_addr] = (target_addr + aligned_size, offset, vf)
            os.lseek(vf.descriptor, original_off, os.SEEK_SET)

        self.__allocations[target_addr] = aligned_size
        
        return target_addr

    def find_free_region(self, size: int, start_search: int = 0) -> int:
        """
        Finds a continuous unmapped memory region. 
        Slow operation: O(n) where n is number of mapped regions.
        """
        regions = sorted(self.__mu.mem_regions())
        
        search_base = max(self._brk_ptr + 0x1000000, page_end(start_search))
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
            self.__mu.mem_unmap(start, aligned_size)
            self.__allocations.pop(start, None)
            self.__file_map_addr.pop(start, None)
            return 0
        except unicorn.UcError:
            return -1

    def protect(self, addr: int, size: int, prot: int) -> int:
        """Change memory protection."""
        try:
            self.__mu.mem_protect(page_start(addr), page_end(size), prot)
            return 0
        except unicorn.UcError:
            return -1

    def __read_fully(self, fd: int, size: int) -> bytes:
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
        return self.__mu.mem_regions()

    def dump_maps(self, stream: 'io.StringIO') -> None:
        """Write current memory map to a stream."""
        regions = sorted(self.__mu.mem_regions())
        stream.write(f"{'Start':<10} {'End':<10} {'Prot':<5}\n")
        for start, end, prot in regions:
            stream.write(f"{start:08x}-{end+1:08x} {prot:<5}\n")

    @property
    def current_brk(self) -> int:
        """Get the current counter-allocation pointer."""
        return self._brk_ptr