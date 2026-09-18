import struct
from typing import TYPE_CHECKING

from ....const import emu_const
from ....const.linux import (
    AT_FDCWD, AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW,
    ENOENT, EBADF, F_GETFL, F_SETFL, EINVAL
)
from ....utils.files import helpers as misc_utils
from ....utils.memory import helpers as memory_helpers

if TYPE_CHECKING:
    from androidemu import Emulator

class FileSystemManager:
    """
    Stateless VFS metadata & filesystem management syscalls.
    """

    def __init__(self) -> None:
        pass

    def _write_stat(self, emu: 'Emulator', buf_ptr: int, stat_obj) -> None:
        if emu.arch == emu_const.ARCH_ARM32:
            misc_utils.stat_to_memory2(emu.mu, buf_ptr, stat_obj)
        else:
            misc_utils.stat_to_memory64(emu.mu, buf_ptr, stat_obj)

    def _stat64(self, emu: 'Emulator', filename_ptr: int, buf_ptr: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, filename_ptr) if filename_ptr else ""
        st = emu.vfs.stat(AT_FDCWD, path, follow_symlinks=True)
        if not st:
            return -ENOENT
        self._write_stat(emu, buf_ptr, st)
        return 0

    def _lstat64(self, emu: 'Emulator', filename_ptr: int, buf_ptr: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, filename_ptr) if filename_ptr else ""
        st = emu.vfs.stat(AT_FDCWD, path, follow_symlinks=False)
        if not st:
            return -ENOENT
        self._write_stat(emu, buf_ptr, st)
        return 0

    def _fstat64(self, emu: 'Emulator', fd: int, stat_ptr: int) -> int:
        st = emu.vfs.fstat(fd)
        if not st:
            return -EBADF
        self._write_stat(emu, stat_ptr, st)
        return 0

    def _fstatat64(self, emu: 'Emulator', dirfd: int, pathname_ptr: int, buf: int, flags: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, pathname_ptr) if pathname_ptr else ""
        norm_dirfd = memory_helpers.normalize_dirfd(dirfd)

        if (flags & AT_EMPTY_PATH and not path) or not path:
            st = emu.vfs.fstat(norm_dirfd)
        else:
            follow = not bool(flags & AT_SYMLINK_NOFOLLOW)
            st = emu.vfs.stat(norm_dirfd, path, follow_symlinks=follow)

        if not st:
            return -ENOENT

        self._write_stat(emu, buf, st)
        return 0

    def _getdents64(self, emu: 'Emulator', fd: int, ptr: int, count: int) -> int:
        ret, data = emu.vfs.getdents64(fd, count)
        if ret > 0:
            emu.mu.mem_write(ptr, data)
        return ret

    def _access(self, emu: 'Emulator', filename_ptr: int, mode: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, filename_ptr) if filename_ptr else ""
        node = emu.vfs.resolve_node(AT_FDCWD, path, follow_symlinks=True)
        return 0 if node else -ENOENT

    def _faccessat(self, emu: 'Emulator', dirfd: int, pathname_ptr: int, mode: int, flags: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, pathname_ptr) if pathname_ptr else ""
        norm_dirfd = memory_helpers.normalize_dirfd(dirfd)
        follow = not bool(flags & AT_SYMLINK_NOFOLLOW)
        node = emu.vfs.resolve_node(norm_dirfd, path, follow_symlinks=follow)
        return 0 if node else -ENOENT

    def _readlinkat(self, emu: 'Emulator', dfd: int, path_ptr: int, buf: int, bufsz: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, path_ptr) if path_ptr else ""
        norm_dfd = memory_helpers.normalize_dirfd(dfd)
        target = emu.vfs.readlink(norm_dfd, path)
        if not target:
            return -ENOENT

        data = target.encode("utf-8")
        size = min(len(data), bufsz)
        emu.mu.mem_write(buf, data[:size])
        return size

    def _unlink(self, emu: 'Emulator', path_ptr: int) -> int:
        return 0  # Dummy success

    def _unlinkat(self, emu: 'Emulator', dfd: int, path_ptr: int, flags: int) -> int:
        return 0  # Dummy success

    def _linkat(self, emu: 'Emulator', olddirfd: int, oldpath_ptr: int, newdirfd: int, newpath_ptr: int, flags: int) -> int:
        return 0  # Dummy success

    def _fcntl(self, emu: 'Emulator', fd: int, cmd: int, arg1: int, arg2: int, arg3: int, arg4: int) -> int:
        handle = emu.vfs.get_handle(fd)
        if not handle:
            return -EBADF

        if cmd == F_GETFL:
            return handle.flags | 0x8000
        elif cmd == F_SETFL:
            handle.flags = arg1
            return 0
        return 0

    def _mkdir(self, emu: 'Emulator', path_ptr: int, mode: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, path_ptr) if path_ptr else ""
        if not path:
            return -EINVAL
        return emu.vfs.mkdir(AT_FDCWD, path, mode)

    def _mkdirat(self, emu: 'Emulator', dfd: int, path_ptr: int, mode: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, path_ptr) if path_ptr else ""
        if not path:
            return -EINVAL
            
        norm_dirfd = memory_helpers.normalize_dirfd(dfd)
        return emu.vfs.mkdir(norm_dirfd, path, mode)

    def _statfs64(self, emu: 'Emulator', path_ptr: int, sz: int, buf: int) -> int:
        emu.mu.mem_write(buf, struct.pack(
            "<QQQQQQQQQQ",
            0xEF53,   # f_type (EXT4_SUPER_MAGIC)
            4096,     # f_bsize
            2097152,  # f_blocks (8GB)
            1048576,  # f_bfree
            1048576,  # f_bavail
            524288,   # f_files
            500000,   # f_ffree
            0,        # f_fsid
            255,      # f_namelen
            4096      # f_frsize
        ))
        return 0