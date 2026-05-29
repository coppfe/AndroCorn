import os

from ....utils.memory import helpers as memory_helpers

from ....const.linux import *

from ....types import ptr_t

from ...dev.ioctl import IoctlHandler

from typing import TYPE_CHECKING

from ....types.alias import *
from ....runtime.precompile import define

if TYPE_CHECKING:
    from unicorn import Uc
    from ....core.process.pcb import ProcessControlBlock
    from .helpers._io import FileSystemIOUtils
    from .helpers.utils import FileSystemUtils


class FileSystemIO:
    def __init__(self, mu: 'Uc', pcb: 'ProcessControlBlock', fs_io_helper: 'FileSystemIOUtils', fs_helper: 'FileSystemUtils'):
        self._mu = mu
        self._pcb = pcb

        self._fs_io = fs_io_helper
        self._fs = fs_helper

        self._ptr_size = ptr_t.size

        self._ioctl_cb = IoctlHandler(self._mu)

    # =========================================================
    # FD HELPER (UNIFIED ACCESS)
    # =========================================================

    def _fd(self, fd):
        return self._pcb.virtual_files.get_fd_detail(fd)

    # =========================================================
    # IOCTL / POLL
    # =========================================================

    def _ioctl(self, mu, fd, cmd, a1, a2, a3, a4):
        return self._ioctl_cb.handle(fd, cmd, a1, a2, a3, a4)

    def _poll(self, mu, pollfd_ptr, nfds, timeout):
        return self._fs_io._do_poll(mu, pollfd_ptr, nfds, timeout)

    def _ppoll(self, mu, pollfd_ptr, nfds, timeout_ts_ptr, sigmask_ptr):
        timeout = -1

        if timeout_ts_ptr:
            ptr_sz = self._ptr_size
            sec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr, ptr_sz)
            nsec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr + ptr_sz, ptr_sz)
            timeout = int(sec * 1000 + nsec / 1_000_000)

        return self._fs_io._do_poll(mu, pollfd_ptr, nfds, timeout)

    # =========================================================
    # OPEN / CLOSE
    # =========================================================

    def _open(self, mu, filename_ptr, flags, mode):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self._fs_io._open_file(mu, path, flags)

    def _openat(self, mu, dfd, filename_ptr, flags, mode):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self._fs_io._open_file(mu, path, flags)

    def _close(self, mu, fd):
        return self._fs_io._close_file(mu, fd)

    # =========================================================
    # SEEK
    # =========================================================

    @define
    def _lseek(self, mu, fd: int32_t, offset: off_t, whence: int32_t):
        # // off_t lseek(int fd, off_t offset, int whence);
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

        ptr_sz = self._ptr_size
        vec_sz = 2 * ptr_sz

        total = bytearray()

        for i in range(vlen):
            addr = memory_helpers.read_ptr_sz(mu, vec + i * vec_sz)
            size = memory_helpers.read_ptr_sz(mu, vec + i * vec_sz + ptr_sz)
            total += mu.mem_read(addr, size)
        return vf.write(total)

    # =========================================================
    # ACCESS / FS OPS
    # =========================================================

    def _mkdir(self, mu, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)
        host = self._fs._translate_path(path)

        if not os.path.exists(host):
            os.makedirs(host)

        return 0

    def _mkdirat(self, mu, dfd, path_ptr, mode):
        path = self._fs._dirfd_2_path(dfd, memory_helpers.read_utf8(mu, path_ptr))
        if not path:
            return -EPERM

        host = self._fs._translate_path(path)

        if not os.path.exists(host):
            os.makedirs(host)

        return 0
