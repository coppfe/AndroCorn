import logging
import os
import platform

from .....utils.memory import memory_helpers
from .....utils.files import file_helpers

from .....const import emu_const
from .....const.linux import *
from .....const.metatags import *

from .....objects.virtual_file import VirtualFile
from .helpers.ioctl import IoctlHandler

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator
    from .....pcb import Pcb
    from .helpers.fs_io_helpers import FSIOHelpers
    from .helpers.fs_helpers import FSHelpers


class VirtualFileIOCalls:
    def __init__(self, emulator: 'Emulator', fs_io_helper: 'FSIOHelpers', fs_helper: 'FSHelpers'):
        self.__emu = emulator
        self.__pcb: 'Pcb' = emulator.pcb

        self.__fs_io = fs_io_helper
        self.__fs = fs_helper
        self.__ioctl = IoctlHandler(self.__emu.mu)

        self._is_win = platform.system() == "Windows"

        self._sig_maps = {}

    # =========================================================
    # FD HELPER (UNIFIED ACCESS)
    # =========================================================

    def _fd(self, fd):
        return self.__pcb.virtual_files.get_fd_detail(fd)

    # =========================================================
    # IOCTL / POLL
    # =========================================================

    @PROXY
    def _ioctl(self, mu, fd, cmd, a1, a2, a3, a4):
        return self.__ioctl.handle(fd, cmd, a1, a2, a3, a4)

    @PROXY
    def _poll(self, mu, pollfd_ptr, nfds, timeout):
        return self.__fs_io._do_poll(mu, pollfd_ptr, nfds, timeout)

    @PROXY
    def _ppoll(self, mu, pollfd_ptr, nfds, timeout_ts_ptr, sigmask_ptr):
        timeout = -1

        if timeout_ts_ptr:
            ptr_sz = self.__emu.ptr_size
            sec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr, ptr_sz)
            nsec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr + ptr_sz, ptr_sz)
            timeout = int(sec * 1000 + nsec / 1_000_000)

        return self.__fs_io._do_poll(mu, pollfd_ptr, nfds, timeout)

    # =========================================================
    # OPEN / CLOSE
    # =========================================================

    @PROXY
    def _open(self, mu, filename_ptr, flags, mode):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self.__fs_io._open_file(mu, path, flags)

    @PROXY
    def _openat(self, mu, dfd, filename_ptr, flags, mode):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self.__fs_io._open_file(mu, path, flags)

    @PROXY
    def _close(self, mu, fd):
        return self.__fs_io._close_file(mu, fd)

    # =========================================================
    # SEEK
    # =========================================================

    def _lseek(self, mu, fd, offset, whence):
        vf = self._fd(fd)
        if not vf:
            return -EBADF
        return vf.seek(offset, whence)

    def _llseek(self, mu, fd, hi, lo, result_ptr, whence):
        vf = self._fd(fd)
        if not vf:
            return -EBADF

        offset = (hi << 32) | (lo & 0xffffffff)
        new_off = vf.seek(offset, whence)

        if new_off < 0:
            return -EINVAL

        try:
            mu.mem_write(result_ptr, new_off.to_bytes(8, "little"))
        except Exception:
            return -EFAULT

        return 0

    # =========================================================
    # READ / WRITE
    # =========================================================

    def _read(self, mu, fd, buf_addr, count):
        vf = self._fd(fd)
        if not vf:
            return -EBADF
        return vf.read(buf_addr, count)

    def _write(self, mu, fd, buf_addr, count):
        vf = self._fd(fd)
        if not vf:
            return -EBADF

        data = mu.mem_read(buf_addr, count)
        return vf.write(data)

    def _writev(self, mu, fd, vec, vlen):
        vf = self._fd(fd)
        if not vf:
            return -EBADF

        ptr_sz = self.__emu.ptr_size
        vec_sz = 2 * ptr_sz

        total = bytearray()

        for i in range(vlen):
            addr = memory_helpers.read_ptr_sz(mu, vec + i * vec_sz, ptr_sz)
            size = memory_helpers.read_ptr_sz(mu, vec + i * vec_sz + ptr_sz, ptr_sz)
            total += mu.mem_read(addr, size)

        return vf.write(total)

    # =========================================================
    # STAT / FSTAT
    # =========================================================

    def _fstat64(self, mu, fd, stat_ptr):
        vf = self._fd(fd)
        if not vf:
            return -EBADF

        stats = self.__fs._make_stat_object(vf.name, vfile=vf)
        if not stats:
            return -EPERM

        writer = file_helpers.stat_to_memory2 if self.__emu.arch == emu_const.ARCH_ARM32 else file_helpers.stat_to_memory64

        writer(
            mu,
            stat_ptr,
            stats,
            stats.st_uid,
            stats.st_mode,
            self.__emu.config
        )

        return 0

    # =========================================================
    # ACCESS / FS OPS
    # =========================================================

    def _access(self, mu, filename_ptr, flags):
        path = memory_helpers.read_utf8(mu, filename_ptr)

        if self.__fs.is_virtual(path):
            return 0

        host = self.__fs._translate_path(path)
        return 0 if os.access(host, flags) else -EPERM

    def _mkdir(self, mu, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)
        host = self.__fs._translate_path(path)

        if not os.path.exists(host):
            os.makedirs(host)

        return 0

    def _mkdirat(self, mu, dfd, path_ptr, mode):
        path = self.__fs._dirfd_2_path(dfd, memory_helpers.read_utf8(mu, path_ptr))
        if not path:
            return -EPERM

        host = self.__fs._translate_path(path)

        if not os.path.exists(host):
            os.makedirs(host)

        return 0