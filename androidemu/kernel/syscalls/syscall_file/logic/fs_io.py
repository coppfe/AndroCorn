import logging
import os
import platform

from .....utils.memory import memory_helpers
from .....utils.parsers.android.logcat import LogCatParser

from .....const.linux import *
from .....const.metatags import *


from .helpers.ioctl import IoctlHandler

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator
    from ....pcb import Pcb
    from .....utils.generators.vfs_content import ContentGenerator
    from .helpers.fs_io_helpers import FSIOHelpers
    from .helpers.fs_helpers import FSHelpers


class VirtualFileIOCalls:
    def __init__(self, emulator: 'Emulator', fs_io_helper: 'FSIOHelpers', fs_helper: 'FSHelpers'):
        self.__emu: 'Emulator' = emulator
        self.__pcb: 'Pcb' = self.__emu.pcb

        self.__fs_io_helpers = fs_io_helper
        self.__fs_helpers = fs_helper
        self.__ioctl_handler = IoctlHandler(self.__emu.mu)

        # self.__tid = self.__emu.scheduler.get_current_tid()
        self._sig_maps = {}
        
        self.g_isWin = platform.system() == "Windows"

        if logging.root.level <= logging.INFO:
            self.log_cat_parser = LogCatParser()

    @PROXY
    def _ioctl(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        # https://manpages.debian.org/testing/manpages-dev/ioctl_list.2.en.html

        return self.__ioctl_handler.handle(fd, cmd, arg1, arg2, arg3, arg4)
    
    @PROXY
    def _poll(self, mu, pollfd_ptr, nfds, timeout):
        return self.__fs_io_helpers._do_poll(mu, pollfd_ptr, nfds, timeout)
    
    @PROXY
    def _ppoll(self, mu, pollfd_ptr, nfds, timeout_ts_ptr, sigmask_ptr):
        timeout = -1
        if timeout_ts_ptr != 0:
            ptr_sz = self.__emu.ptr_size
            tv_sec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr, ptr_sz)
            tv_nsec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr + ptr_sz, ptr_sz)
            timeout = int(tv_sec * 1000 + tv_nsec / 1000000)
    
        return self.__fs_io_helpers._do_poll(mu, pollfd_ptr, nfds, timeout)

    @PROXY
    def _open(self, mu, filename_ptr, flags, mode):
        """
        int open(const char *pathname, int flags, mode_t mode);

        return the new file descriptor, or -1 if an error occurred (in which case, errno is set appropriately).
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        return self.__fs_io_helpers._open_file(mu, filename, flags)
    
    @PROXY
    def _openat(self, mu, dfd, filename_ptr, flags, mode):
        """
        int openat(int dirfd, const char *pathname, int flags, mode_t mode);

        On success, openat() returns a new file descriptor.
        On error, -1 is returned and errno is set to indicate the error.

        EBADF
            dirfd is not a valid file descriptor.
        ENOTDIR
            pathname is relative and dirfd is a file descriptor referring to a file other than a directory.
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        filepath = self.__fs_helpers._dirfd_2_path(dfd, filename)
        if (filepath == None):
            return -1
        return self.__fs_io_helpers._open_file(mu, filename, flags)
    
    @PROXY
    def _close(self, mu, fd):
        """
        int close(int fd);

        close() closes a file descriptor, so that it no longer refers to any file and may be reused. Any record locks
        (see fcntl(2)) held on the file it was associated with, and owned by the process, are removed (regardless of
        the file descriptor that was used to obtain the lock).

        close() returns zero on success. On error, -1 is returned, and errno is set appropriately.
        """

        return self.__fs_io_helpers._close_file(mu, fd)
    
    def _lseek(self, mu, fd, offset, whence):
        file = self.__pcb.virtual_files.get_fd_detail(fd)
        if not file:
            return -1 # EBADF

        if file.is_virtual:
            if whence == 0: # SEEK_SET
                file.offset = offset
            elif whence == 1: # SEEK_CUR
                file.offset += offset
            return file.offset

        try:
            real_fd = file.descriptor 
            return os.lseek(real_fd, offset, whence)
        
        except OSError as e:

            logging.warning(f"lseek caused an OS error at fd {fd}: {e}")
            return -1
        
    def _llseek(self, mu, fd, offset_high, offset_low, result_ptr, whence):
        if (offset_high != 0):
            raise RuntimeError("_llseek offset_high %d>0 not implemented"%offset_high)

        n = os.lseek(fd, offset_low, whence)
        r = -1

        if (n > 0xFFFFFFFF):
            raise RuntimeError("_llseek return > 32 bits not implemented!!!")
        
        if (n >= 0):

            r = 0
            rbytes = n.to_bytes(8, 'little')
            mu.mem_write(result_ptr, rbytes)
            
        return r

    def _read(self, mu, fd, buf_addr, count):
        virtual_file = self.__pcb.virtual_files.get_fd_detail(fd)
        if virtual_file:
            return virtual_file.read(buf_addr, count)
        else:
            logging.warning("File read '%s' error skip", virtual_file.name)

    def _write(self, mu, fd, buf_addr, count):
        virtual_file = self.__pcb.virtual_files.get_fd_detail(fd)
        if virtual_file:
            return virtual_file.write(mu.mem_read(buf_addr, count))
        else:
            logging.warning("File write '%s' error skip", virtual_file.name)

    def _writev(self, mu, fd, vec, vlen):
        ptr_sz = self.__emu.ptr_size
        vec_sz = 2*ptr_sz
        file = self.__pcb.virtual_files.get_fd_detail(fd)

        total_data = bytearray()

        for i in range(vlen):
            addr = memory_helpers.read_ptr_sz(mu, vec + (i * vec_sz), ptr_sz)
            size = memory_helpers.read_ptr_sz(mu, vec + (i * vec_sz) + ptr_sz, ptr_sz)
            total_data += mu.mem_read(addr, size)

        if logging.root.level <= logging.INFO:
            self.log_cat_parser.feed(total_data)
            print(self.log_cat_parser.get_entries(clear=True))

        return file.write(total_data)