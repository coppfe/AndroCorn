from typing import TYPE_CHECKING

from ..backend.filesystem import FileSystemIO, FileSystemManager
from ..backend.memory import MemorySyscalls
from ..backend.selinux import SELinuxHandler
from ..backend.sysproc import (
    NetworkSyscalls,
    ProcessSyscalls,
    SignalSyscalls,
    SystemSyscalls,
    TimeSyscalls,
)
if TYPE_CHECKING:
    from androidemu.core import Emulator


class CallbacksARM64:
    def __init__(self, emu: 'Emulator'):
        
        self._io_calls = FileSystemIO()
        self._system_calls = FileSystemManager()
        self._process_syscalls = ProcessSyscalls()
        self._network_syscalls = NetworkSyscalls()
        self._system_syscalls = SystemSyscalls(emu.config)
        self._signal_syscalls = SignalSyscalls()
        self._memory_syscalls = MemorySyscalls()
        self._time_syscalls = TimeSyscalls()
        self._selinux_syscalls = SELinuxHandler()


        sysproc = {
            0x18:  ("dup3",             3, self._process_syscalls._dup3),
            0x3B:  ("pipe2",            2, self._process_syscalls._pipe2),
            0x5D:  ("exit",             1, self._process_syscalls._exit),
            0x5E:  ("exit_group",       1, self._process_syscalls._exit),
            0x60:  ("set_tid_address",  1, self._process_syscalls._set_tid_address),
            0x62:  ("futex",            6, self._process_syscalls._futex),
            0x65:  ("nanosleep",        2, self._time_syscalls._nanosleep),
            0x71:  ("clock_gettime",    2, self._time_syscalls._clock_gettime),
            0x75:  ("ptrace",           4, self._process_syscalls._ptrace),
            0x81:  ("kill",             2, self._signal_syscalls._kill),
            0x83:  ("tgkill",           3, self._signal_syscalls._tgkill),
            0x84:  ("sigaltstack",      2, self._signal_syscalls._sigaltstack),
            0x86:  ("rt_sigaction",     4, self._signal_syscalls._rt_sigaction),
            0x87:  ("rt_sigprocmask",   4, self._signal_syscalls._rt_sigprocmask),
            0x94:  ("getresuid",        3, self._process_syscalls._getresuid32),
            0xA0:  ("uname",            1, self._system_syscalls._uname),
            0xA3:  ("getrlimit",        2, self._system_syscalls._getrlimit),
            0xA7:  ("prctl",            5, self._system_syscalls._prctl),
            0xA8:  ("getcpu",           3, self._system_syscalls._getcpu),
            0xA9:  ("gettimeofday",     2, self._time_syscalls._gettimeofday),
            0xAC:  ("getpid",           0, self._process_syscalls._getpid),
            0xAD:  ("getppid",          0, self._process_syscalls._getppid),
            0xAE:  ("getuid",           0, self._process_syscalls._getuid),
            0xAF:  ("geteuid",          0, self._process_syscalls._geteuid),
            0xB2:  ("gettid",           0, self._process_syscalls._gettid),
            0xB3:  ("sysinfo",          1, self._system_syscalls._sysinfo),
            0xC6:  ("socket",           3, self._network_syscalls._socket),
            0xC8:  ("bind",             3, self._network_syscalls._bind),
            0xCB:  ("connect",          3, self._network_syscalls._connect),
            0xD0:  ("setsockopt",       5, self._network_syscalls._setsockopt),
            0xDC:  ("clone",            5, self._process_syscalls._clone),
            0xDD:  ("execve",           3, self._process_syscalls._execve),
            0xE1:  ("swapoff",          1, self._system_syscalls._swapoff),
            0x104: ("wait4",            4, self._process_syscalls._wait4),
            0x116: ("getrandom",        3, self._system_syscalls._getrandom),
        }

        memory = {
            0xD6:  ("brk",               1, self._memory_syscalls._handle_brk),
            0xD7:  ("munmap",            2, self._memory_syscalls._handle_munmap),
            0xDE:  ("mmap",              6, self._memory_syscalls._handle_mmap),
            0xE2:  ("mprotect",          3, self._memory_syscalls._handle_mprotect),
            0xE9:  ("madvise",           3, self._memory_syscalls._handle_madvise),
            0x10E: ("process_vm_readv",  6, self._memory_syscalls._handle_process_vm_readv),
        }

        filesystem = {
            0x19: ("fcntl",       6, self._system_calls._fcntl),
            0x1D: ("ioctl",       6, self._io_calls._ioctl),
            0x22: ("mkdirat",     3, self._system_calls._mkdirat),
            0x23: ("unlinkat",    3, self._system_calls._unlinkat),
            0x2B: ("statfs",      3, self._system_calls._statfs64),
            0x30: ("faccessat",   4, self._system_calls._faccessat),
            0x38: ("openat",      4, self._io_calls._openat),
            0x39: ("close",       1, self._io_calls._close),
            0x3D: ("getdents64",  3, self._system_calls._getdents64),
            0x3E: ("lseek",       3, self._io_calls._lseek),
            0x3F: ("read",        3, self._io_calls._read),
            0x40: ("write",       3, self._io_calls._write),
            0x42: ("writev",      3, self._io_calls._writev),
            0x49: ("ppoll",       4, self._io_calls._ppoll),
            0x4E: ("readlinkat",  4, self._system_calls._readlinkat),
            0x4F: ("newfstatat",  4, self._system_calls._fstatat64),
            0x50: ("fstat",       2, self._system_calls._fstat64),
        }

        selinux = {
            # 0x05: ("setxattr",    5, self._selinux_syscalls._setxattr),
            # 0x06: ("lsetxattr",   5, self._selinux_syscalls._setxattr),
            # 0x07: ("fsetxattr",   5, self._selinux_syscalls._setxattr),
            0x08: ("getxattr",      4, self._selinux_syscalls._getxattr),
            0x09: ("lgetxattr",     4, self._selinux_syscalls._lgetxattr),
            0x0A: ("fgetxattr",     4, self._selinux_syscalls._fgetxattr),
            # 0x0B: ("listxattr",   3, self._selinux_syscalls._listxattr),
            # 0x0C: ("llistxattr",  3, self._selinux_syscalls._listxattr),
            # 0x0D: ("flistxattr",  3, self._selinux_syscalls._listxattr),
        }

        self._syscall_table = {}
        self._syscall_table.update(sysproc)
        self._syscall_table.update(memory)
        self._syscall_table.update(filesystem)
        self._syscall_table.update(selinux)