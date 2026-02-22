from typing import TYPE_CHECKING
from unicorn import UC_PROT_READ, UC_PROT_WRITE
from ..const import emu_const
import logging
from ..config import STACK_ADDR

import logging
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..emulator import Emulator
    from ..pcb import Pcb
    from ..cpu.syscall_handlers import SyscallHandlers
    from .memory_map import MemoryMap

class MemorySyscallHandler:
    """
    """
    def __init__(self, emu: 'Emulator', memory: 'MemoryMap', syscall_handler: 'SyscallHandlers'):
        self.__emu: 'Emulator' = emu
        self.__pcb: 'Pcb' = emu.get_pcb()
        self._memory: 'MemoryMap' = memory
        self._syscall_handler: 'SyscallHandlers' = syscall_handler
        self.current_brk = 0

        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            # Memory
            self._syscall_handler.set_handler(0x2d, "brk", 1, self._handle_brk)
            self._syscall_handler.set_handler(0x5B, "munmap", 2, self._handle_munmap)
            self._syscall_handler.set_handler(0x7D, "mprotect", 3, self._handle_mprotect)
            self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
            self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)
            
            self._syscall_handler.set_handler(0xF0, "futex", 6, self._handle_futex)
            self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
            
            # Identity
            self._syscall_handler.set_handler(0x14, "getpid", 0, self._handle_getpid)
            self._syscall_handler.set_handler(0xE0, "gettid", 0, self._handle_gettid)
            self._syscall_handler.set_handler(0xC7, "getuid32", 0, self._handle_getuid)
            self._syscall_handler.set_handler(0x18, "getuid", 0, self._handle_getuid)

        # --- ARM 64-bit Syscalls ---
        else:
            # Memory
            self._syscall_handler.set_handler(0xd6, "brk", 1, self._handle_brk)
            self._syscall_handler.set_handler(0xd7, "munmap", 2, self._handle_munmap)
            self._syscall_handler.set_handler(0xe2, "mprotect", 3, self._handle_mprotect)
            self._syscall_handler.set_handler(0xde, "mmap", 6, self._handle_mmap)
            self._syscall_handler.set_handler(0xe9, "madvise", 3, self._handle_madvise)
            
            # Synchronization & Process
            self._syscall_handler.set_handler(0x62, "futex", 6, self._handle_futex)
            self._syscall_handler.set_handler(0xa7, "prctl", 5, self._handle_prctl)
            
            # Identity
            self._syscall_handler.set_handler(0xac, "getpid", 0, self._handle_getpid)
            self._syscall_handler.set_handler(0xb2, "gettid", 0, self._handle_gettid)
            self._syscall_handler.set_handler(0xad, "getuid", 0, self._handle_getuid)
    
    def _handle_brk(self, mu, brk_addr):
        """
        sys_brk syscall handler.
        Modern Android relies mostly on mmap, but brk is still queried at startup.
        """
        if not hasattr(self, '_brk_base'):
            self._brk_size = 0x800000  # 8 MB
            self._brk_base = self._memory.map(0, self._brk_size, UC_PROT_READ | UC_PROT_WRITE)
            self._brk_current = self._brk_base
            self._brk_max = self._brk_base + self._brk_size
            
            logger.debug(f" Initialized brk heap at {hex(self._brk_base)} - {hex(self._brk_max)}")

        if brk_addr == 0:
            return self._brk_current

        if brk_addr < self._brk_base or brk_addr >= self._brk_max:
            return self._brk_current

        self._brk_current = brk_addr
        return self._brk_current

    def _handle_munmap(self, uc, addr, len_in):
        #TODO: set errno
        return self._memory.unmap(addr, len_in)
    #

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
        MAP_ANONYMOUS = 0x20
        #define MAP_UNINITIALIZED 0x0
        res = None
        if flags & MAP_ANONYMOUS:
            res = self._memory.map(addr, length, prot)
        elif fd != 0xffffffff: # 如果有fd
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
            #
            if not self.__pcb.has_fd(fd):
                # TODO: Return valid error.
                raise NotImplementedError()

            vf = self.__pcb.get_fd_detail(fd)
            #mmap2 系统调用最后一个参数与mmap不同,注意阅读下面一句话!
            '''
            The mmap2() system call provides the same interface as mmap(2),
            except that the final argument specifies the offset into the file in
            4096-byte units (instead of bytes, as is done by mmap(2)).  This
            enables applications that use a 32-bit off_t to map large files (up
            to 2^44 bytes).
            '''
            offset = pgoffset * 4096
            res = self._memory.map(addr, length, prot, vf, offset)
        #
        else:
            res = self._memory.map(addr, length, prot)
        #
        # print(f"mmap2(0x{addr:08X}, 0x{length:08X}, 0x{prot:08X}, 0x{flags:08X}, 0x{fd:08X}, 0x{pgoffset:08X})")
        logging.debug("mmap return 0x%08X"%res)
        return res
    #

    def _handle_prctl(self, uc, option, arg2, arg3, arg4, arg5):
        # PR_SET_VMA = 0x53564d41 (used by Android to name memory maps)
        # PR_SET_NAME = 15
        if option == 0x53564d41: 
            # Android specific: prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, len, name)
            # Just ignore, it's for debug naming
            return 0
        return 0

    def _handle_futex(self, uc, uaddr, op, val, timeout, uaddr2, val3):
        """
        Futex is CRITICAL for jemalloc/scudo. 
        Without it, malloc deadlocks trying to lock its own structures.
        """
        # op codes:
        # FUTEX_WAIT = 0
        # FUTEX_WAKE = 1
        # FUTEX_WAIT_BITSET = 9
        # ...
        
        cmd = op & 0x7F # Mask out PRIVATE/CLOCK_REALTIME flags
        
        if cmd == 0 or cmd == 9: # WAIT
            # Pretend we waited and everything is fine. 
            # Returning 0 means "condition met/no error".
            # For emulation, since we are single-threaded (mostly), we don't need real blocking.
            return 0 
            
        elif cmd == 1: # WAKE
            # Return number of woken processes. 
            # Return 0 or 1 is usually safe for malloc.
            return 0
            
        return 0

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
        elif fd != 0xffffffff: # 如果有fd
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
            #
            if not self.__pcb.has_fd(fd):
                # TODO: Return valid error.
                raise NotImplementedError()

            vf = self.__pcb.get_fd_detail(fd)
            res = self._memory.map(addr, length, prot, vf, offset)
        #
        else:
            res = self._memory.map(addr, length, prot)
        #
        logging.debug("mmap return 0x%016X"%res)
        return res
    #

    def _handle_getpid(self, uc):
        return self.__emu.pid
    
    def _handle_gettid(self, uc):
        return self.__emu.tid

    def _handle_getuid(self, uc):
        return self.__emu.uid

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
    #
