from ....const import emu_const
from ..syscall_handlers import SyscallHandlers

from .logic.process import ProcessSyscalls
from .logic.system import SystemSyscalls
from .logic.virtual_time import VirtualTimeSyscall
from .logic.signals import SignalSyscalls
from .logic.network import NetworkSyscalls

from unicorn import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ....emulator import Emulator
    
class SyscallHooks:

    #system call table
    #https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm-32_bit_EABI
    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """

    def __init__(self, emu: 'Emulator', syscall_handler: 'SyscallHandlers'):
        self.__emu = emu
        
        self._syscall_handler: 'SyscallHandlers' = syscall_handler
        
        self._process_syscalls = ProcessSyscalls(emu)
        self._system_syscalls = SystemSyscalls(emu)
        self._virtual_time_syscalls = VirtualTimeSyscall(emu)
        self._signal_syscalls = SignalSyscalls(emu)
        self._network_syscalls = NetworkSyscalls(emu)

        if (self.__emu.arch == emu_const.ARCH_ARM32):
            #arm32
            self._syscall_handler.set_handler(0x1,     "exit",            1, self._process_syscalls._exit)
            self._syscall_handler.set_handler(0x2,     "fork",            0, self._process_syscalls._fork)
            self._syscall_handler.set_handler(0x0B,    "execve",          3, self._process_syscalls._execve)
            self._syscall_handler.set_handler(0x14,    "getpid",          0, self._process_syscalls._getpid)
            self._syscall_handler.set_handler(0x18,    "getuid",          0, self._process_syscalls._getuid)
            self._syscall_handler.set_handler(0x1A,    "ptrace",          4, self._process_syscalls._ptrace)
            self._syscall_handler.set_handler(0x25,    "kill",            2, self._signal_syscalls._kill)
            self._syscall_handler.set_handler(0x2A,    "pipe",            1, self._process_syscalls._pipe)
            self._syscall_handler.set_handler(0x43,    "sigaction",       3, self._signal_syscalls._sigaction)
            self._syscall_handler.set_handler(0x4E,    "gettimeofday",    2, self._virtual_time_syscalls._gettimeofday)
            self._syscall_handler.set_handler(0x72,    "wait4",           4, self._process_syscalls._wait4)
            self._syscall_handler.set_handler(0x74,    "sysinfo",         1, self._system_syscalls._sysinfo)
            self._syscall_handler.set_handler(0x78,    "clone",           5, self._process_syscalls._clone)
            self._syscall_handler.set_handler(0x7A,    "uname",           1, self._system_syscalls._uname)
            self._syscall_handler.set_handler(0x7E,    "sigprocmask",     3, self._signal_syscalls._sigprocmask)
            self._syscall_handler.set_handler(0xAC,    "prctl",           5, self._system_syscalls._prctl)
            self._syscall_handler.set_handler(0xAE,    "rt_sigaction",    4, self._signal_syscalls._rt_sigaction)
            self._syscall_handler.set_handler(0xAF,    "rt_sigprocmask",  4, self._signal_syscalls._rt_sigprocmask)
            self._syscall_handler.set_handler(0xBA,    "sigaltstack",     2, self._signal_syscalls._sigaltstack)
            self._syscall_handler.set_handler(0xBE,    "vfork",           0, self._process_syscalls._vfork)
            self._syscall_handler.set_handler(0xC7,    "getuid32",        0, self._process_syscalls._getuid)
            self._syscall_handler.set_handler(0xDA,    "set_tid_address", 1, self._process_syscalls._set_tid_address)
            self._syscall_handler.set_handler(0xE0,    "gettid",          0, self._process_syscalls._gettid)
            self._syscall_handler.set_handler(0xF0,    "futex",           6, self._process_syscalls._futex)
            self._syscall_handler.set_handler(0x10c,   "tgkill",          3, self._signal_syscalls._tgkill)
            self._syscall_handler.set_handler(0x107,   "clock_gettime",   2, self._virtual_time_syscalls._clock_gettime)
            self._syscall_handler.set_handler(0x119,   "socket",          3, self._network_syscalls._socket)
            self._syscall_handler.set_handler(0x11a,   "bind",            3, self._network_syscalls._bind)
            self._syscall_handler.set_handler(0x11b,   "connect",         3, self._network_syscalls._connect)
            self._syscall_handler.set_handler(0x126,   "setsockopt",      5, self._network_syscalls._setsockopt)
            self._syscall_handler.set_handler(0x159,   "getcpu",          3, self._system_syscalls._getcpu)
            self._syscall_handler.set_handler(0x166,   "dup3",            3, self._process_syscalls._dup3)
            self._syscall_handler.set_handler(0x167,   "pipe2",           2, self._process_syscalls._pipe2)
            self._syscall_handler.set_handler(0x180,   "getrandom",       3, self._system_syscalls._getrandom)
            self._syscall_handler.set_handler(0xa2,    "nanosleep",       2, self._virtual_time_syscalls._nanosleep)
            self._syscall_handler.set_handler(0xf0002, "ARM_cacheflush",  0, self._process_syscalls._ARM_cacheflush)
            self._syscall_handler.set_handler(0xf0005, "ARM_set_tls",     1, self._process_syscalls._ARM_set_tls)
        else:
            #arm64
            self._syscall_handler.set_handler(0x5D,    "exit",            1, self._process_syscalls._exit)
            self._syscall_handler.set_handler(0xDC,    "clone",           5, self._process_syscalls._clone)
            self._syscall_handler.set_handler(0xDD,    "execve",          3, self._process_syscalls._execve)
            self._syscall_handler.set_handler(0xAC,    "getpid",          0, self._process_syscalls._getpid)
            self._syscall_handler.set_handler(0xAE,    "getuid",          0, self._process_syscalls._getuid)
            self._syscall_handler.set_handler(0x75,    "ptrace",          4, self._process_syscalls._ptrace)
            self._syscall_handler.set_handler(0x104,   "wait4",           4, self._process_syscalls._wait4)
            self._syscall_handler.set_handler(0xB2,    "gettid",          0, self._process_syscalls._gettid)
            self._syscall_handler.set_handler(0x62,    "futex",           6, self._process_syscalls._futex)
            self._syscall_handler.set_handler(0x81,    "kill",            2, self._signal_syscalls._kill)
            self._syscall_handler.set_handler(0x86,    "rt_sigaction",    4, self._signal_syscalls._rt_sigaction)
            self._syscall_handler.set_handler(0x87,    "rt_sigprocmask",  4, self._signal_syscalls._rt_sigprocmask)
            self._syscall_handler.set_handler(0x84,    "sigaltstack",     2, self._signal_syscalls._sigaltstack)
            self._syscall_handler.set_handler(0x83,    "tgkill",          3, self._signal_syscalls._tgkill)
            self._syscall_handler.set_handler(0xA9,    "gettimeofday",    2, self._virtual_time_syscalls._gettimeofday)
            self._syscall_handler.set_handler(0x71,    "clock_gettime",   2, self._virtual_time_syscalls._clock_gettime)
            self._syscall_handler.set_handler(0x65,    "nanosleep",       2, self._virtual_time_syscalls._nanosleep)
            self._syscall_handler.set_handler(0xB3,    "sysinfo",         1, self._system_syscalls._sysinfo)
            self._syscall_handler.set_handler(0xA0,    "uname",           1, self._system_syscalls._uname)
            self._syscall_handler.set_handler(0xA7,    "prctl",           5, self._system_syscalls._prctl)
            self._syscall_handler.set_handler(0xA8,    "getcpu",          3, self._system_syscalls._getcpu)
            self._syscall_handler.set_handler(0x116,   "getrandom",       3, self._system_syscalls._getrandom)
            self._syscall_handler.set_handler(0xC6,    "socket",          3, self._network_syscalls._socket)
            self._syscall_handler.set_handler(0xC8,    "bind",            3, self._network_syscalls._bind)
            self._syscall_handler.set_handler(0xCB,    "connect",         3, self._network_syscalls._connect)
            self._syscall_handler.set_handler(0xD0,    "setsockopt",      5, self._network_syscalls._setsockopt)
            self._syscall_handler.set_handler(0x18,    "dup3",            3, self._process_syscalls._dup3)
            self._syscall_handler.set_handler(0x3B,    "pipe2",           2, self._process_syscalls._pipe2)

    # def __any_call(self, mu: 'Uc', syscall_id, args, a0, a1, a2, a3, a4, a5):
    #     call core
    #     self.__libc.syscall