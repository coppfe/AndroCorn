import os
import logging
import unicorn
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_ALL, UC_ERR_MAP
from ..utils.misc_utils import page_end, page_start

PAGE_SIZE = 0x1000

class MemoryMap:
    def __init__(self, mu, alloc_min_addr, alloc_max_addr):
        self.__mu = mu
        self._alloc_min_addr = alloc_min_addr
        self._alloc_max_addr = alloc_max_addr
        self.__file_map_addr = {} # {addr: (end, offset, vf)}
        self.__allocations = {}   # {addr: size}

    @staticmethod
    def __is_page_align(addr):
        return addr % PAGE_SIZE == 0

    @staticmethod
    def __is_overlap(addr1, end1, addr2, end2):
        return max(addr1, addr2) < min(end1, end2)

    def __read_fully(self, fd, size):
        data = b""
        while size > 0:
            chunk = os.read(fd, size)
            if not chunk: break
            data += chunk
            size -= len(chunk)
        return data

    def __find_free_region(self, size):
        """
        Ищет свободную дырку нужного размера.
        """
        regions = sorted(self.__mu.mem_regions())
        
        candidate = self._alloc_min_addr
        
        for r_start, r_end, _ in regions:
            r_limit = r_end + 1
            
            if r_start > candidate:
                if (r_start - candidate) >= size:
                    return candidate
            
            if r_limit > candidate:
                candidate = (r_limit + 0xFFF) & ~0xFFF # Align 4K
        
        if candidate + size > self._alloc_max_addr:
            raise RuntimeError(f"Out of address space! Can't find {hex(size)} bytes.")
            
        return candidate

    def map(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE, vf=None, offset=0):
        if size <= 0:
            raise ValueError("Size must be > 0")

        al_size = ((size + 0xFFF) & ~0xFFF)
        
        if address == 0:
            target_addr = self.__find_free_region(al_size)
        else:
            if not self.__is_page_align(address):
                raise RuntimeError(f"Address {hex(address)} not page aligned")
            target_addr = address

        try:
            self.__mu.mem_map(target_addr, al_size, prot)
        except unicorn.UcError as e:
            if e.errno == UC_ERR_MAP:
                try:
                    self.__mu.mem_unmap(target_addr, al_size)
                    self.__mu.mem_map(target_addr, al_size, prot)
                except unicorn.UcError:
                    self.__mu.mem_protect(target_addr, al_size, prot)
            else:
                raise e

        if vf is not None:
            if not self.__is_page_align(offset):
                pass
            
            ori_off = os.lseek(vf.descriptor, 0, os.SEEK_CUR)
            os.lseek(vf.descriptor, offset, os.SEEK_SET)
            
            data = self.__read_fully(vf.descriptor, size)
            if data:
                self.__mu.mem_write(target_addr, data)
            
            self.__file_map_addr[target_addr] = (target_addr + al_size, offset, vf)
            os.lseek(vf.descriptor, ori_off, os.SEEK_SET)

        self.__allocations[target_addr] = al_size
        return target_addr

    def unmap(self, addr, size):
        if not self.__is_page_align(addr):
             addr = page_start(addr)
        
        al_size = ((size + 0xFFF) & ~0xFFF)
        try:
            self.__mu.mem_unmap(addr, al_size)
            if addr in self.__allocations:
                del self.__allocations[addr]
            if addr in self.__file_map_addr:
                del self.__file_map_addr[addr]
            return 0
        except unicorn.UcError:
            return -1

    def protect(self, addr, size, prot):
        al_size = ((size + 0xFFF) & ~0xFFF)
        try:
            self.__mu.mem_protect(addr, al_size, prot)
            return 0
        except unicorn.UcError:
            return -1
            
    def dump_maps(self, stream):
        regions = sorted(self.__mu.mem_regions())
        for start, end, prot in regions:
            stream.write(f"{start:08x}-{end+1:08x} {prot}\n")