import logging
import os
import platform
import struct

from .....utils.memory import memory_helpers
from .....utils.files import file_helpers
from .....const.metatags import *
from .....const import emu_const
from .....const.linux import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator
    from .....pcb import Pcb
    from .....utils.generators.vfs_content import ContentGenerator
    from .helpers.fs_helpers import FSHelpers

if platform.system() == "Linux":
    import fcntl


class VirtualFileSystemCalls:
    def __init__(self, emulator: 'Emulator', content_generator: 'ContentGenerator', fs_helper: 'FSHelpers'):
        self.__emu: 'Emulator' = emulator
        self.__pcb: 'Pcb' = emulator.pcb

        self.__generator = content_generator
        self.__fs = fs_helper

        self._is_win = platform.system() == "Windows"

    # =========================================================
    # PATH RESOLUTION CORE
    # =========================================================

    def _resolve(self, dfd, path_ptr):
        path = memory_helpers.read_utf8(self.__emu.mu, path_ptr)
        return self.__fs._dirfd_2_path(dfd, path)

    def _host(self, virt_path: str):
        return self.__fs._translate_path(virt_path)

    # =========================================================
    # SYMLINK LAYER HELPERS
    # =========================================================

    def _symlink_get(self, path: str):
        return self.__pcb.virtual_files.get_symlink_target(path)

    def _symlink_set(self, src: str, dst: str):
        self.__pcb.virtual_files.add_symlink(dst, src)

    def _symlink_remove(self, path: str):
        self.__pcb.virtual_files.remove_symlink(path)

    # =========================================================
    # STAT FAMILY
    # =========================================================

    @PROXY
    def _stat64(self, mu, filename_ptr, buf_ptr):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self.__fs._internal_path_stat_handler(mu, path, buf_ptr, True)

    @PROXY
    def _lstat64(self, mu, filename_ptr, buf_ptr):
        path = memory_helpers.read_utf8(mu, filename_ptr)
        return self.__fs._internal_path_stat_handler(mu, path, buf_ptr, False)

    @PROXY
    def _fstat64(self, mu, fd, stat_ptr):
        vf = self.__pcb.virtual_files.get_fd_detail(fd)
        if not vf:
            return -EBADF

        stats = self.__fs._make_stat_object(vf.name, vfile=vf)
        if not stats:
            return -EPERM

        is_arm32 = self.__emu.arch == emu_const.ARCH_ARM32
        writer = file_helpers.stat_to_memory2 if is_arm32 else file_helpers.stat_to_memory64

        writer(mu, stat_ptr, stats, stats.st_uid, stats.st_mode, self.__emu.config)
        return 0

    @PROXY
    def _fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        path = self._resolve(dirfd, pathname_ptr)
        if not path:
            return -EPERM

        follow = not (flags & 0x100)  # AT_SYMLINK_NOFOLLOW
        return self.__fs._internal_path_stat_handler(mu, path, buf, follow)

    # =========================================================
    # FILE CONTROL
    # =========================================================

    @PROXY
    def _fcntl(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        if self._is_win:
            return 0

        try:
            return fcntl.fcntl(fd, cmd, arg1)
        except OSError:
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

        # fd = self.__pcb.virtual_files.get_fd_by_name(virt_path)
        # if fd is not None:
        #     self.__pcb.virtual_files.remove_fd(fd)
        #     return 0

        return -EPERM

    # =========================================================
    # READLINK FAMILY
    # =========================================================

    def _readlinkat(self, mu, dfd, path_ptr, buf, bufsz):
        virt = self._resolve(dfd, path_ptr)
        if not virt:
            return -ENOENT

        target = self._symlink_get(virt)
        if not target:
            # maybe then it's a virtual?
            is_virtual = self.__generator.is_virtual(virt)
            if is_virtual:
                target = self.__generator.generate(virt)
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

    def _getdents64(self, mu, fd, ptr, count):
        entry = self.__pcb.virtual_files.get_fd_detail(fd)
        if not entry:
            return -EBADF

        if entry.offset > 0:
            return 0

        data = self.__generator.resolve_dir_entries(
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
            return -EPERM

        if self.__generator.is_virtual(path):
            return 0

        host = self._host(path)
        return 0 if os.access(host, mode) else -EPERM
    
    def _access(self, mu, filename_ptr, flags):
        path = self._resolve(0, filename_ptr)
        return self._do_access(path, flags)

    def _faccessat(self, mu, dirfd, pathname_ptr, mode, flag):
        filename = memory_helpers.read_utf8(mu, pathname_ptr)

        logging.debug("faccessat filename:[%s]", filename)

        path = self.__fs._dirfd_2_path(dirfd, filename)
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