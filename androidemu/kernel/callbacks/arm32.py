from ..backend.memory import MemorySyscalls
from ..backend.sysproc import ProcessSyscalls
from ..backend.sysproc import NetworkSyscalls
from ..backend.sysproc import SystemSyscalls
from ..backend.sysproc import SignalSyscalls
from ..backend.sysproc import TimeSyscalls
from ..backend.sysproc.arm import ARMSyscalls
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

class CallbacksARM32:
    def __init__(
        self, process: 'ProcessArgumentsBlock', system: "SystemArgumentsBlock"
    ):
        super().__init__()

        self._ARM_cacheflush = success("ARM_cacheflush")

        self._arm_syscalls = ARMSyscalls(process.tls)
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
            0x1: ("exit", 1, self._process_syscalls._exit),
            0x2: ("fork", 0, self._process_syscalls._fork),
            0x0B: ("execve", 3, self._process_syscalls._execve),
            0x14: ("getpid", 0, self._process_syscalls._getpid),
            0x18: ("getuid", 0, self._process_syscalls._getuid),
            0x1A: ("ptrace", 4, self._process_syscalls._ptrace),
            0x25: ("kill", 2, self._signal_syscalls._kill),
            0x2A: ("pipe", 1, self._process_syscalls._pipe),
            0x43: ("sigaction", 3, self._signal_syscalls._sigaction),
            0x4E: ("gettimeofday", 2, self._time_syscalls._gettimeofday),
            0x72: ("wait4", 4, self._process_syscalls._wait4),
            0x74: ("sysinfo", 1, self._system_syscalls._sysinfo),
            0x78: ("clone", 5, self._process_syscalls._clone),
            0x7A: ("uname", 1, self._system_syscalls._uname),
            0x7E: ("sigprocmask", 3, self._signal_syscalls._sigprocmask),
            0xA2: ("nanosleep", 2, self._time_syscalls._nanosleep),
            0xAC: ("prctl", 5, self._system_syscalls._prctl),
            0xAE: ("rt_sigaction", 4, self._signal_syscalls._rt_sigaction),
            0xAF: ("rt_sigprocmask", 4, self._signal_syscalls._rt_sigprocmask),
            0xBA: ("sigaltstack", 2, self._signal_syscalls._sigaltstack),
            0xBE: ("vfork", 0, self._process_syscalls._vfork),
            0xBF: ("getrlimit", 2, self._system_syscalls._getrlimit),
            0xC7: ("getuid32", 0, self._process_syscalls._getuid),
            0xC9: ("geteuid32", 0, self._process_syscalls._geteuid),
            0x40: ("getppid", 0, self._process_syscalls._getppid),
            0xDA: ("set_tid_address", 1, self._process_syscalls._set_tid_address),
            0xE0: ("gettid", 0, self._process_syscalls._gettid),
            0xF0: ("futex", 6, self._process_syscalls._futex),
            0xF8: ("exit_group", 1, self._process_syscalls._exit),
            0xD1: ("getresuid32", 3, self._process_syscalls._getresuid32),
            0x107: ("clock_gettime", 2, self._time_syscalls._clock_gettime),
            0x10C: ("tgkill", 3, self._signal_syscalls._tgkill),
            0x119: ("socket", 3, self._network_syscalls._socket),
            0x11A: ("bind", 3, self._network_syscalls._bind),
            0x11B: ("connect", 3, self._network_syscalls._connect),
            0x126: ("setsockopt", 5, self._network_syscalls._setsockopt),
            0x159: ("getcpu", 3, self._system_syscalls._getcpu),
            0x166: ("dup3", 3, self._process_syscalls._dup3),
            0x167: ("pipe2", 2, self._process_syscalls._pipe2),
            0x180: ("getrandom", 3, self._system_syscalls._getrandom),
            0xF0002: ("ARM_cacheflush", 0, self._ARM_cacheflush),
            0xF0005: ("ARM_set_tls", 1, self._arm_syscalls._ARM_set_tls),
        }

        memory = {
            0x2D: ("brk", 1, self._memory_syscalls._handle_brk),
            0x5B: ("munmap", 2, self._memory_syscalls._handle_munmap),
            0x7D: ("mprotect", 3, self._memory_syscalls._handle_mprotect),
            0xC0: ("mmap2", 6, self._memory_syscalls._handle_mmap2),
            0xDC: ("madvise", 3, self._memory_syscalls._handle_madvise),
            0x178:("process_vm_readv", 6, self._memory_syscalls._handle_process_vm_readv)
        }

        filesystem = {
            0x03: ("read", 3, self._io_calls._read),
            0x04: ("write", 3, self._io_calls._write),
            0x06: ("close", 1, self._io_calls._close),
            0x13: ("lseek", 3, self._io_calls._lseek),
            0x36: ("ioctl", 6, self._io_calls._ioctl),
            0x8C: ("_llseek", 5, self._io_calls._llseek),
            0x92: ("writev", 3, self._io_calls._writev),
            0xA8: ("poll", 3, self._io_calls._poll),
            0x150: ("ppoll", 4, self._io_calls._ppoll),
            0x05: ("open", 3, self._io_calls._open),
            0x142: ("openat", 4, self._io_calls._openat),
            0x0A: ("unlink", 1, self._system_calls._unlink),
            0x21: ("access", 2, self._system_calls._access),
            0x27: ("mkdir", 2, self._system_calls._mkdir),
            0x37: ("fcntl", 6, self._system_calls._fcntl),
            0x6C: ("fstat", 2, self._system_calls._fstat64),
            0xC3: ("stat64", 2, self._system_calls._stat64),
            0xC4: ("lstat64", 2, self._system_calls._lstat64),
            0xC5: ("fstat64", 2, self._system_calls._fstat64),
            0xD9: ("getdents64", 3, self._system_calls._getdents64),
            0xDD: ("fcntl64", 6, self._system_calls._fcntl),
            0x10A: ("statfs64", 3, self._system_calls._statfs64),
            0x143: ("mkdirat", 3, self._system_calls._mkdirat),
            0x147: ("fstatat64", 4, self._system_calls._fstatat64),
            0x149: ("linkat", 4, self._system_calls._linkat),
            0x148: ("unlinkat", 3, self._system_calls._unlinkat),
            0x14C: ("readlinkat", 4, self._system_calls._readlinkat),
            0x14E: ("faccessat", 4, self._system_calls._faccessat),
        }

        self._syscall_table = {}


        self._syscall_table.update(sysproc)
        self._syscall_table.update(memory)
        self._syscall_table.update(filesystem)