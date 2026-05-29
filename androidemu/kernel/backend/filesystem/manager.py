import logging
import os
import struct

from ....utils.memory import helpers as memory_helpers
from ....utils.files import helpers as misc_utils
from ....const import emu_const
from ....const.linux import *

from ....types.alias import _os

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc
    from ....core.process.pcb import ProcessControlBlock
    from ...dev.content import ContentGenerator
    from .helpers.utils import FileSystemUtils

if _os == 'Linux':
    import fcntl


class FileSystemManager:
    def __init__(self, mu: 'Uc', pcb: 'ProcessControlBlock', content_generator: 'ContentGenerator', fs_helper: 'FileSystemUtils'):
        self._mu = mu
        self._pcb = pcb

        self._generator: 'ContentGenerator' = content_generator
        self._fs = fs_helper

    # =========================================================
    # PATH RESOLUTION CORE
    # =========================================================

    def _resolve(self, dfd, path_ptr):
        path = memory_helpers.read_utf8(self._mu, path_ptr)
        return self._fs._dirfd_2_path(dfd, path)

    def _host(self, virt_path: str):
        return self._fs._translate_path(virt_path)

    # =========================================================
    # SYMLINK LAYER HELPERS
    # =========================================================

    def _symlink_get(self, path: str):
        return self._pcb.virtual_files.get_symlink_target(path)

    def _symlink_set(self, src: str, dst: str):
        self._pcb.virtual_files.add_symlink(dst, src)

    def _symlink_remove(self, path: str):
        self._pcb.virtual_files.remove_symlink(path)

    # =========================================================
    # STAT FAMILY
    # =========================================================

    def _stat64(self, mu, filename_ptr, buf_ptr):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self._fs._internal_path_stat_handler(mu, path, buf_ptr, True)

    def _lstat64(self, mu, filename_ptr, buf_ptr):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self._fs._internal_path_stat_handler(mu, path, buf_ptr, False)

    def _fstat64(self, mu, fd, stat_ptr):
        vf = self._pcb.virtual_files.get_fd_detail(fd)
        if not vf:
            return -EBADF

        accs = self._do_access(vf.name, 0)
        if accs != 0:
            return accs

        stats = self._fs._make_stat_object(vf)
        if not stats:
            return -EPERM

        is_arm32 = self._mu._arch == emu_const.ARCH_ARM32
        writer = misc_utils.stat_to_memory2 if is_arm32 else misc_utils.stat_to_memory64

        writer(mu, stat_ptr, stats)
        return 0

    def _fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        path = memory_helpers.read_utf8(self._mu, pathname_ptr) if pathname_ptr else ""
        if (flags & AT_EMPTY_PATH) and not path:
            return self._fstat64(mu, dirfd, buf)
        full_path = self._resolve(dirfd, pathname_ptr)

        if not full_path:
            return -ENOENT
        
        accs = self._do_access(full_path, 0)
        if accs != 0:
            return accs

        follow = not (flags & AT_SYMLINK_NOFOLLOW)

        return self._fs._internal_path_stat_handler(mu, full_path, buf, follow)

    # =========================================================
    # FILE CONTROL
    # =========================================================

    def _fcntl(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        # BUG: Remove fcntl module!!! Not working on Windows and not working with Virtual Files.
        vf = self._pcb.virtual_files.get_fd_detail(fd)
        if not vf:
            return -EBADF

        if cmd == F_GETFL:
            if vf.is_virtual:
                return 0x8000

            try:
                return fcntl.fcntl(vf.descriptor, cmd, arg1)
            except Exception as e:
                logging.warning(f"FCNTL returned error {e.__class__.__name__}: {e}. Return const value 0x8000")
                return 0x8000

        return 0
    # =========================================================
    # UNLINK FAMILY (CLEAN VFS)
    # =========================================================

    def _unlinkat(self, mu, dfd, path_ptr, flags):
        virt = self._resolve(dfd, path_ptr)
        if not virt:
            return -ENOENT  # ENOENT

        return self._unlink_virtual(virt)

    def _unlink(self, mu, path_ptr):
        path = memory_helpers.read_utf8(mu, path_ptr)
        return self._unlink_virtual(path)

    def _unlink_virtual(self, virt_path: str):
        # symlink removal
        if self._symlink_get(virt_path):
            self._symlink_remove(virt_path)
            return 0

        # fd = self._pcb.virtual_files.get_fd_by_name(virt_path)
        # if fd is not None:
        #     self._pcb.virtual_files.remove_fd(fd)
        #     return 0

        return -EPERM

    # =========================================================
    # READLINK FAMILY
    # =========================================================

    def _readlinkat(self, mu: 'Uc', dfd, path_ptr, buf, bufsz):
        virt = self._resolve(dfd, path_ptr)
        if not virt:
            return -ENOENT

        target = self._symlink_get(virt)
        if not target:
            # maybe then it's a virtual?
            is_virtual = self._generator.is_virtual(virt)
            if is_virtual:
                target = self._generator.generate(virt)
            else:
                return -ENOENT

        data = target.encode("utf-8")
        size = min(len(data), bufsz)

        mu.mem_write(buf, data[:size])
        logging.debug("readlinkat: %s -> %s", virt, target)
        return size

    # =========================================================
    # LINK FAMILY
    # =========================================================

    def _linkat(self, mu, olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags):
        old = self._resolve(olddirfd, oldpath_ptr)
        new = self._resolve(newdirfd, newpath_ptr)

        if not old or not new:
            return -EPERM

        self._symlink_set(old, new)

        logging.debug("linkat: %s -> %s", old, new)
        return 0

    # =========================================================
    # DIRECTORY ENTRIES
    # =========================================================

    def _getdents64(self, mu: 'Uc', fd, ptr, count):
        entry = self._pcb.virtual_files.get_fd_detail(fd)
        if not entry:
            return -EBADF

        if entry.offset > 0:
            return 0

        data = self._generator.resolve_dir_entries(
            entry.name,
            entry.name_in_system,
            fd=fd
        )

        if not data:
            return 0

        chunk = data[:count]
        mu.mem_write(ptr, chunk)

        entry.offset = len(chunk)
        return len(chunk)

    # =========================================================
    # ACCESS / FS OPERATIONS
    # =========================================================

    def _do_access(self, path: str, mode: int):
        if not path:
            return -ENOENT

        if self._generator.is_virtual(path):
            return 0

        host = self._host(path)
        if os.path.exists(host):
            return 0 if os.access(host, mode) else -EPERM
        else:
            return -ENOENT

    def _access(self, mu, filename_ptr, flags):
        path = self._resolve(0, filename_ptr)
        return self._do_access(path, flags)

    def _faccessat(self, mu, dirfd, pathname_ptr, mode, flag):
        filename = memory_helpers.read_utf8(mu, pathname_ptr)

        logging.debug("faccessat filename:[%s]", filename)
        path = self._fs._dirfd_2_path(dirfd, filename)
        if path is None:
            return -EPERM

        return self._do_access(path, mode)

    def _mkdir(self, mu, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)
        host = self._host(path)

        if not os.path.exists(host):
            os.makedirs(host)

        return 0

    def _mkdirat(self, mu, dfd, path_ptr, mode):
        path = self._resolve(dfd, path_ptr)
        if not path:
            return -EPERM

        host = self._host(path)

        if not os.path.exists(host):
            os.makedirs(host)

        return 0

    # =========================================================
    # STATFS
    # =========================================================

    def _statfs64(self, mu, path_ptr, sz, buf):
        path = memory_helpers.read_utf8(mu, path_ptr)
        host = self._host(path)

        if not os.path.exists(host):
            return -EPERM

        statv = os.statvfs(host)

        mu.mem_write(buf, struct.pack(
            "<QQQQQQQQQQ",
            0xef53,
            statv.f_bsize,
            statv.f_blocks,
            statv.f_bfree,
            statv.f_bavail,
            statv.f_files,
            statv.f_ffree,
            getattr(statv, "f_fsid", 0),
            statv.f_namemax,
            statv.f_frsize
        ))

        return 0
