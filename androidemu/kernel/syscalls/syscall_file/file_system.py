from ....const.linux import *
from ....const import emu_const
from ....utils.generators.vfs_content import ContentGenerator

from .logic.fs_io import VirtualFileIOCalls
from .logic.fs_manager import VirtualFileSystemCalls

from .logic.helpers.fs_helpers import FSHelpers
from .logic.helpers.fs_io_helpers import FSIOHelpers

from .logic.helpers.fs_helpers import FSHelpers

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ....emulator import Emulator
    from ..syscall_handlers import SyscallHandlers

class VirtualFileSystem:
    def __init__(self, emu: 'Emulator', root_path: str, syscall_handler: 'SyscallHandlers'):
        self.__emu = emu

        # Utils
        self.__generator = ContentGenerator(self.__emu)

        self.__fs_helper = FSHelpers(emu, self.__generator, root_path)
        self.__fs_io_helper = FSIOHelpers(emu, self.__generator, self.__fs_helper)

        self.__system_calls = VirtualFileSystemCalls(emu, self.__generator, self.__fs_helper)
        self.__io_calls = VirtualFileIOCalls(emu, self.__fs_io_helper, self.__fs_helper)

        self.__fs_helper._clear_proc_dir()
        
        # maybe sort by syscall num...

        if self.__emu.arch == emu_const.ARCH_ARM32:
            syscall_handler.set_handler(0x03, "read", 3, self.__io_calls._read)
            syscall_handler.set_handler(0x04, "write", 3, self.__io_calls._write)
            syscall_handler.set_handler(0x06, "close", 1, self.__io_calls._close)
            syscall_handler.set_handler(0x13, "lseek", 3, self.__io_calls._lseek)
            syscall_handler.set_handler(0x36, "ioctl", 6, self.__io_calls._ioctl)
            syscall_handler.set_handler(0x8c, "_llseek", 5, self.__io_calls._llseek)
            syscall_handler.set_handler(0x92, "writev", 3, self.__io_calls._writev)
            syscall_handler.set_handler(0xA8, "poll", 3, self.__io_calls._poll)
            syscall_handler.set_handler(0x150, "ppoll", 4, self.__io_calls._ppoll)
            syscall_handler.set_handler(0x05, "open", 3, self.__io_calls._open)
            syscall_handler.set_handler(0x142, "openat", 4, self.__io_calls._openat)

            syscall_handler.set_handler(0x0A, "unlink", 1, self.__system_calls._unlink)
            syscall_handler.set_handler(0x21, "access", 2, self.__system_calls._access)
            syscall_handler.set_handler(0x27, "mkdir", 2, self.__system_calls._mkdir)
            syscall_handler.set_handler(0x37, "fcntl", 6, self.__system_calls._fcntl)
            syscall_handler.set_handler(0x6C, "fstat", 2, self.__system_calls._fstat64)
            syscall_handler.set_handler(0xC3, "stat64", 2, self.__system_calls._stat64)
            syscall_handler.set_handler(0xC4, "lstat64", 2, self.__system_calls._lstat64)
            syscall_handler.set_handler(0xC5, "fstat64", 2, self.__system_calls._fstat64)
            syscall_handler.set_handler(0xD9, "getdents64", 3, self.__system_calls._getdents64)
            syscall_handler.set_handler(0xDD, "fcntl64", 6, self.__system_calls._fcntl)
            syscall_handler.set_handler(0x10A, "statfs64", 3, self.__system_calls._statfs64)
            
            syscall_handler.set_handler(0x143, "mkdirat", 3, self.__system_calls._mkdirat)
            syscall_handler.set_handler(0x147, "fstatat64", 4, self.__system_calls._fstatat64)
            syscall_handler.set_handler(0x148, "unlinkat", 3, self.__system_calls._unlinkat)
            syscall_handler.set_handler(0x14c, "readlinkat", 4, self.__system_calls._readlinkat)
            syscall_handler.set_handler(0x14e, "faccessat", 4, self.__system_calls._faccessat)

        else:
            syscall_handler.set_handler(0x3f, "read", 3, self.__io_calls._read)
            syscall_handler.set_handler(0x40, "write", 3, self.__io_calls._write)
            syscall_handler.set_handler(0x39, "close", 1, self.__io_calls._close)
            syscall_handler.set_handler(0x3e, "lseek", 3, self.__io_calls._lseek)
            syscall_handler.set_handler(0x1d, "ioctl", 6, self.__io_calls._ioctl)
            syscall_handler.set_handler(0x42, "writev", 3, self.__io_calls._writev)
            syscall_handler.set_handler(0x49, "ppoll", 4, self.__io_calls._ppoll)
            syscall_handler.set_handler(0x38, "openat", 4, self.__io_calls._openat)
            
            syscall_handler.set_handler(0x19, "fcntl", 6, self.__system_calls._fcntl)
            syscall_handler.set_handler(0x50, "fstat", 2, self.__system_calls._fstat64)
            syscall_handler.set_handler(0x3D, "getdents64", 3, self.__system_calls._getdents64)
            syscall_handler.set_handler(0x2B, "statfs", 3, self.__system_calls._statfs64)
            
            syscall_handler.set_handler(0x22, "mkdirat", 3, self.__system_calls._mkdirat)
            syscall_handler.set_handler(0x23, "unlinkat", 3, self.__system_calls._unlinkat)
            syscall_handler.set_handler(0x4E, "readlinkat", 4, self.__system_calls._readlinkat)
            syscall_handler.set_handler(0x30, "faccessat", 4, self.__system_calls._faccessat)
            syscall_handler.set_handler(0x4F, "newfstatat", 4, self.__system_calls._fstatat64)