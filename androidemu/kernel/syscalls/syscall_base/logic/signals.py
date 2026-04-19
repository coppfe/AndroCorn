import logging
import os
import ctypes
import time
import sys
import socket
from random import randint

from unicorn import Uc
from unicorn.arm_const import *

from .....const.android import *
from .....const.linux import *
from .....const import emu_const
from .....const.metatags import *
from ...syscall_handlers import SyscallHandlers
from .....utils.memory import memory_helpers
from .....objects.virtual_file import VirtualFile
from unicorn import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator


class SignalSyscalls:
    def __init__(self, emulator: 'Emulator'):
        self.__emu: 'Emulator' = emulator

        self.__ptr_sz = self.__emu.ptr_size
        self.__pid = self.__emu.pcb.pid
        # self.__tid = self.__emu.scheduler.get_current_tid()
        self._sig_maps = {}

    def _kill(self, mu, pid, sig):
        logging.debug("kill is call pid=0x%x sig=%d"%(pid, sig))
        if (pid == self.__pid):
            logging.error("process 0x%x is killing self!!! maybe encounter anti-debug!!!"%pid)
            sys.exit(-10)

    def _tgkill(self, mu, tgid, tid, sig):
        if (tgid ==  self.__pid and sig == 6):
            raise RuntimeError("tgkill abort self....")
        return 0
        # if (tgid == self.__pid and tid == self.__tid):
        #     if (sig in self._sig_maps):

        #         sigact = self._sig_maps[sig]
        #         addr = sigact[0]
        #         #TODO implement signal handling
        #         return 0
        #     #
        # #
        # raise NotImplementedError()
        # return 0

    def _sigaction(self, mu: 'Uc', sig: int, act: int, oact: int):
        '''
        struct sigaction {
            union {
                void     (*sa_handler)(int);
                void     (*sa_sigaction)(int, siginfo_t *, void *);
            },
            sigset_t   sa_mask;
            int        sa_flags;
            void     (*sa_restorer)(void);
        };
        '''
        act_off = act
        sa_handler = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_mask = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_flag = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_restorer = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)

        logging.debug("sa_handler [0x%08X] sa_mask [0x%08X] sa_flag [0x%08X] sa_restorer [0x%08X]"%(sa_handler, sa_mask, sa_flag, sa_restorer))
        self._sig_maps[sig] = (sa_handler, sa_mask, sa_flag, sa_restorer)
        return 0
    
    def _rt_sigaction(self, mu: 'Uc', sig, act, oact, sigsetsize):
        '''
        struct sigaction {
            union {
                void     (*sa_handler)(int);
                void     (*sa_sigaction)(int, siginfo_t *, void *);
            },
            sigset_t   sa_mask;
            int        sa_flags;
            void     (*sa_restorer)(void);
        };
        '''
        act_off = act
        sa_handler = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        #sigsetsize是sa_mask的大小，64位下一般位8，see https://man7.org/linux/man-pages/man2/sigaction.2.html
        sa_mask = memory_helpers.read_ptr_sz(mu, act_off, sigsetsize)
        act_off+=sigsetsize
        sa_flag = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
        act_off+=self.__ptr_sz
        sa_restorer = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)

        logging.debug("sa_handler [0x%08X] sa_mask [0x%08X] sa_flag [0x%08X] sa_restorer [0x%08X]"%(sa_handler, sa_mask, sa_flag, sa_restorer))
        self._sig_maps[sig] = (sa_handler, sa_mask, sa_flag, sa_restorer)
        return 0
    
    def _sigprocmask(self, mu: 'Uc', how, set, oset):
        return 0
    
    def _rt_sigprocmask(self, mu, how, set, oset, sigsetsize):
        return 0
    
    def _sigaltstack(self, mu, uss, ouss):
        #TODO implment
        return 0