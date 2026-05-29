from ..backend.memory import MemorySyscalls
from ..backend.sysproc import ProcessSyscalls
from ..backend.sysproc import NetworkSyscalls
from ..backend.sysproc import SystemSyscalls
from ..backend.sysproc import SignalSyscalls
from ..backend.sysproc import TimeSyscalls
from ..backend.filesystem import FileSystemIO
from ..backend.filesystem import FileSystemIOUtils
from ..backend.filesystem import FileSystemManager
from ..backend.filesystem import FileSystemUtils

from ..dev.content import ContentGenerator

from ..backend.mocks import success

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.arguments.system import SystemArgumentsBlock
    from androidemu.arguments.process import ProcessArgumentsBlock

class CallbacksARM64:
    def __init__(
        self, process: 'ProcessArgumentsBlock', system: "SystemArgumentsBlock"
    ):
        super().__init__()

        self._process_syscalls = ProcessSyscalls(
            process, system.properties, system.config
        )
        self._network_syscalls = NetworkSyscalls(process.control_block)
        self._system_syscalls = SystemSyscalls(process.mu, system.config, process.ctx)
        self._signal_syscalls = SignalSyscalls(process.emu, process.ctx)
        self._memory_syscalls = MemorySyscalls(process)
        self._time_syscalls = TimeSyscalls(process.scheduler, system.clock)

        self._generator = ContentGenerator(process, system)
        self._fs_helper = FileSystemUtils(
            process.control_block, system.config, self._generator, system.clock, process.ctx, system.mount
        )
        self._fs_io_helper = FileSystemIOUtils(
            process.control_block, self._generator, self._fs_helper
        )
        self._system_calls = FileSystemManager(
            process.mu, process.control_block, self._generator, self._fs_helper
        )
        self._io_calls = FileSystemIO(
            process.mu, process.control_block, self._fs_io_helper, self._fs_helper
        )

        sysproc = {
            0x18:     ("dup3",             3, self._process_syscalls._dup3),
            0x3B:     ("pipe2",            2, self._process_syscalls._pipe2),
            0x5D:     ("exit",             1, self._process_syscalls._exit),
            0x5E:     ("exit_group",       1, self._process_syscalls._exit),
            0x62:     ("futex",            6, self._process_syscalls._futex),
            0x65:     ("nanosleep",        2, self._time_syscalls._nanosleep),
            0x71:     ("clock_gettime",    2, self._time_syscalls._clock_gettime),
            0x75:     ("ptrace",           4, self._process_syscalls._ptrace),
            0x81:     ("kill",             2, self._signal_syscalls._kill),
            0x83:     ("tgkill",           3, self._signal_syscalls._tgkill),
            0x84:     ("sigaltstack",      2, self._signal_syscalls._sigaltstack),
            0x86:     ("rt_sigaction",     4, self._signal_syscalls._rt_sigaction),
            0x87:     ("rt_sigprocmask",   4, self._signal_syscalls._rt_sigprocmask),
            0xA0:     ("uname",            1, self._system_syscalls._uname),
            0xA3:     ("getrlimit",        2, self._system_syscalls._getrlimit),
            0xA7:     ("prctl",            5, self._system_syscalls._prctl),
            0xA8:     ("getcpu",           3, self._system_syscalls._getcpu),
            0xA9:     ("gettimeofday",     2, self._time_syscalls._gettimeofday),
            0xAC:     ("getpid",           0, self._process_syscalls._getpid),
            0xAF:     ("geteuid",          0, self._process_syscalls._geteuid),
            0xAE:     ("getuid",           0, self._process_syscalls._getuid),
            0xB2:     ("gettid",           0, self._process_syscalls._gettid),
            0xB3:     ("sysinfo",          1, self._system_syscalls._sysinfo),
            0xC6:     ("socket",           3, self._network_syscalls._socket),
            0xC8:     ("bind",             3, self._network_syscalls._bind),
            0xCB:     ("connect",          3, self._network_syscalls._connect),
            0xD0:     ("setsockopt",       5, self._network_syscalls._setsockopt),
            0xDC:     ("clone",            5, self._process_syscalls._clone),
            0xDD:     ("execve",           3, self._process_syscalls._execve),
            0x104:    ("wait4",            4, self._process_syscalls._wait4),
            0x116:    ("getrandom",        3, self._system_syscalls._getrandom),
        }

        memory = {
            0xD6: ("brk", 1, self._memory_syscalls._handle_brk),
            0xD7: ("munmap", 2, self._memory_syscalls._handle_munmap),
            0xE2: ("mprotect", 3, self._memory_syscalls._handle_mprotect),
            0xDE: ("mmap2", 6, self._memory_syscalls._handle_mmap2),
            0xE9: ("madvise", 3, self._memory_syscalls._handle_madvise),
            0x10E:("process_vm_readv", 6, self._memory_syscalls._handle_process_vm_readv)
        }

        filesystem = {
            0x3f: ("read", 3, self._io_calls._read),
            0x40: ("write", 3, self._io_calls._write),
            0x39: ("close", 1, self._io_calls._close),
            0x3e: ("lseek", 3, self._io_calls._lseek),
            0x1d: ("ioctl", 6, self._io_calls._ioctl),
            0x42: ("writev", 3, self._io_calls._writev),
            0x49: ("ppoll", 4, self._io_calls._ppoll),
            0x38: ("openat", 4, self._io_calls._openat),
            0x19: ("fcntl", 6, self._system_calls._fcntl),
            0x50: ("fstat", 2, self._system_calls._fstat64),
            0x3D: ("getdents64", 3, self._system_calls._getdents64),
            0x2B: ("statfs", 3, self._system_calls._statfs64),
            0x22: ("mkdirat", 3, self._system_calls._mkdirat),
            0x23: ("unlinkat", 3, self._system_calls._unlinkat),
            0x4E: ("readlinkat", 4, self._system_calls._readlinkat),
            0x30: ("faccessat", 4, self._system_calls._faccessat),
            0x4F: ("newfstatat", 4, self._system_calls._fstatat64),
        }

        self._syscall_table = {}
        
        self._syscall_table.update(sysproc)
        self._syscall_table.update(memory)
        self._syscall_table.update(filesystem)