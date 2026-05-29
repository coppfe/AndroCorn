from typing import TYPE_CHECKING
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from ....const.flags import MAP_ANONYMOUS
from ....const.linux import EBADF
from ....data.mem_map import BRK_SIZE
from ....utils.memory import helpers

from ....types import ptr_t

import logging

if TYPE_CHECKING:
    from ....core.process.pcb import ProcessControlBlock
    from ....utils.memory.map import MemoryMap
    from androidemu.data.states.process import ProcessState
    from androidemu.arguments.process import ProcessArgumentsBlock

# ADD PCB

class MemorySyscalls:
    """
    """
    def __init__(self, process: 'ProcessArgumentsBlock'):
        self._ptr_size = ptr_t.size
        self._pcb: 'ProcessControlBlock' = process.control_block
        self._ctx: 'ProcessState' = process.ctx

        self._memory: 'MemoryMap' = process.memory
        self.current_brk = 0

    def _handle_munmap(self, mu, addr, len_in):
        return self._memory.unmap(addr, len_in)
    
    def _handle_brk(self, mu, brk_addr):
        """
        sys_brk syscall handler.
        Modern Android relies mostly on mmap, but brk is still queried at startup.
        """
        if not hasattr(self, '_brk_base'):

            self._brk_size = BRK_SIZE
            self._brk_base = self._memory.map(0, self._brk_size, UC_PROT_READ | UC_PROT_WRITE)
            self._brk_current = self._brk_base
            self._brk_max = self._brk_base + self._brk_size
            
            logging.debug(" Initialized brk heap at %#x - %#x", self._brk_base, self._brk_max)

        if brk_addr == 0:
            return self._brk_current

        if brk_addr < self._brk_base or brk_addr >= self._brk_max:
            return self._brk_current

        self._brk_current = brk_addr
        return self._brk_current
    
    def _handle_process_vm_readv(self, mu, pid, local_iov, liovcnt, remote_iov, riovcnt, flag):
        '''
        struct iovec {
            void  *iov_base;    /* Starting address */
            size_t iov_len;     /* Number of bytes to transfer */
        };
        '''
        if (pid != self._ctx.pid):
            raise NotImplementedError("__process_vm_readv return other process not support...")
        
        off_r = remote_iov
        b = b''
        
        for i in range(0, riovcnt):
            rbase = helpers.read_ptr_sz(mu, off_r)
            iov_len = helpers.read_ptr_sz(mu, off_r+self._ptr_size)
            tmp = helpers.read_byte_array(mu, rbase, iov_len)
            b+=tmp
            off_r+=2*self._ptr_size

        off_l = local_iov
        has_read = 0

        for j in range(0, liovcnt):
            lbase = helpers.read_ptr_sz(mu, off_l,)
            liov_len = helpers.read_ptr_sz(mu, off_l+self._ptr_size)
            tmp = b[has_read : has_read + liov_len] 
            mu.mem_write(lbase, tmp)
            has_read += len(tmp)
            off_l += 2 * self._ptr_size

        return has_read

    def _handle_mmap2(self, mu, addr, length, prot, flags, fd, pgoffset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """
        #define	PROT_READ	0x04	/* pages can be read */
        #define	PROT_WRITE	0x02	/* pages can be written */
        #define	PROT_EXEC	0x01	/* pages can be executed */
        #define MAP_SHARED 0x01
        #define MAP_PRIVATE 0x02
        #define MAP_TYPE 0x0f
        #define MAP_FIXED 0x10
        #define MAP_UNINITIALIZED 0x0

        res = None
        if flags & MAP_ANONYMOUS:
            res = self._memory.map(addr, length, prot)
        elif fd != 0xffffffff: # If there is fd
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d.", fd)

            if not self._pcb.virtual_files.has_fd(fd):
                return -EBADF

            vf = self._pcb.virtual_files.get_fd_detail(fd)
            #mmap2 The last parameter of the system call differs from that of mmap; pay attention to the following sentence!
            '''
            The mmap2() system call provides the same interface as mmap(2),
            except that the final argument specifies the offset into the file in
            4096-byte units (instead of bytes, as is done by mmap(2)).  This
            enables applications that use a 32-bit off_t to map large files (up
            to 2^44 bytes).
            '''
            offset = pgoffset * 4096
            res = self._memory.map(addr, length, prot, vf, offset)

        else:
            res = self._memory.map(addr, length, prot)
    
        logging.debug("mmap return 0x%08X"%res)
        return res


    def _handle_mmap(self, mu, addr, length, prot, flags, fd, offset):
        """
        void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        """
        #define	PROT_READ	0x04	/* pages can be read */
        #define	PROT_WRITE	0x02	/* pages can be written */
        #define	PROT_EXEC	0x01	/* pages can be executed */
        #define MAP_SHARED 0x01
        #define MAP_PRIVATE 0x02
        #define MAP_TYPE 0x0f
        #define MAP_FIXED 0x10
        MAP_ANONYMOUS = 0x20
        #define MAP_UNINITIALIZED 0x0
        res = None

        if flags & MAP_ANONYMOUS:
            res = self._memory.map(addr, length, prot)

        elif fd != 0xffffffff: # If there is fd
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d.", fd)
    
            if not self._pcb.virtual_files.has_fd(fd):
                # TODO: Return valid error.
                raise NotImplementedError()

            vf = self._pcb.virtual_files.get_fd_detail(fd)
            res = self._memory.map(addr, length, prot, vf, offset)

        else:
            res = self._memory.map(addr, length, prot)

        logging.debug("mmap return 0x%016X"%res)
        return res

    def _handle_madvise(self, mu, start, len_in, behavior):
        """
        int madvise(void *addr, size_t length, int advice);
        The kernel is free to ignore the advice.
        On success madvise() returns zero. On error, it returns -1 and errno is set appropriately.
        """
        # We don't need your advise.
        return 0

    def _handle_mprotect(self, mu, addr, len_in, prot):
        """
        int mprotect(void *addr, size_t len, int prot);

        mprotect() changes protection for the calling process's memory page(s) containing any part of the address
        range in the interval [addr, addr+len-1]. addr must be aligned to a page boundary.
        """
        return self._memory.protect(addr, len_in, prot)
