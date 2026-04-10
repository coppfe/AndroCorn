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

from .helpers.process_helper import ProcessHelper
from .helpers.process_io_helper import ProcessIOHelper

from ....flags import (
    CLONE_CHILD_CLEARTID,
    VFORK_FLAGS,
    FORK_FLAGS,
    THREAD_FLAGS,
    THREAD_TLS_INIT_FLAGS,
    PARENT_SETUP_TID_FLAGS,
    CHILD_SETUP_TID_FLAGS
)

from unicorn import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator


class ProcessSyscalls:
    def __init__(self, emulator: 'Emulator'):
        self.__emu: 'Emulator' = emulator
        self.__proxy: 'ProcessHelper' = ProcessHelper(emulator)
        self.__io_proxy: 'ProcessIOHelper' = ProcessIOHelper(emulator)

        self.__sch = self.__emu.scheduler
        self.__pcb = self.__emu.pcb

        self.__tid_2_tid_addr = {}

    @PROXY
    def _fork(self, mu):
        return self.__proxy._do_fork(mu)
    
    @PROXY
    def _vfork(self, mu):
        return self.__proxy._do_fork(mu)
    
    @PROXY
    def _pipe(self, mu, files_ptr):
        return self.__io_proxy._pipe_common(mu, files_ptr, 0)
    
    @PROXY
    def _pipe2(self, mu, files_ptr, flags):
        return self.__io_proxy._pipe_common(mu, files_ptr, flags)

    def _getpid(self, mu):
        return self.__emu.pid
    
    def _getuid(self, mu):
        return self.__emu.uid
    
    def _gettid(self, mu):
        return self.__emu.scheduler.get_current_tid()
    
    def _ptrace(self, mu, request, pid, addr, data):
        logging.warning("skip syscall ptrace request [%d] pid [0x%x] addr [0x%08X] data [0x%08X]"%(request, pid, addr, data))
        return 0
    
    def _ARM_set_tls(self, mu, tls_ptr):
        assert self.__emu.arch == emu_const.ARCH_ARM32, "error only arm32 has _ARM_set_tls syscall!!!"
        self.__emu.mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)

    def _ARM_cacheflush(self, mu):
        return 0

    def _kill(self, mu, pid, sig):
        logging.warning("kill is call pid=0x%x sig=%d"%(pid, sig))
        if (pid == self._getpid(mu)):
            logging.error("process 0x%x is killing self!!! maybe encounter anti-debug!!!"%pid)
            sys.exit(-10)

    def _dup3(self, mu, oldfd, newfd, flags):
        assert flags == 0, "dup3 flag not support now"
        old_detail = self.__pcb.virtual_files.get_fd_detail(oldfd)
        os.dup2(oldfd, newfd)
        self.__pcb.virtual_files.add_fd(old_detail.name, old_detail.name_in_system, newfd)
        return 0

    def _set_tid_address(self, mu: 'Uc', tidptr):
        sch = self.__sch
        tid = sch.get_current_tid()

        if (not tidptr):
            self.__tid_2_tid_addr.pop(tid)

        else:
            self.__tid_2_tid_addr[tid] = tidptr

        return tid
    
    def _wait4(self, mu, pid, wstatus, options, rusage):
        # https://man7.org/linux/man-pages/man2/wait4.2.html
        assert rusage==0
        
        #return pid
        logging.debug("syscall wait4 pid %d"%pid)
        t = os.wait4(pid, options)
        logging.debug("wait4 return %r"%(t,))
        #wstatus 只是一个int指针，固定是4
        mu.mem_write(wstatus, int(t[1]).to_bytes(4, "little"))
        return t[0]

    def _exit(self, mu: 'Uc', err_code):
        sch = self.__emu.scheduler
        cur_tid = sch.get_current_tid()
        if (cur_tid in self.__tid_2_tid_addr):
            #CLONE_CHILD_CLEARTID 语义，退出时候唤醒线程对应的tid_addr对应的futex
            #这是线程退出自动清理futex的关键
            #见https://man7.org/linux/man-pages/man2/clone.2.html  CLONE_CHILD_CLEARTID描述
            tid_addr_futex = self.__tid_2_tid_addr[cur_tid]
            sch.futex_wake(tid_addr_futex)
            mu.mem_write(tid_addr_futex, int(0).to_bytes(4, byteorder='little'))
            self.__tid_2_tid_addr.pop(cur_tid)
        #
        #TODO use err_code
        sch.exit_current_task()
        return 0
    
    def _execve(self, mu: 'Uc', filename_ptr: int, argv_ptr: int, envp_ptr: int):
        # TODO: beauty
        filename =memory_helpers.read_utf8(mu, filename_ptr)
        ptr = argv_ptr
        params = []
        logging.debug("execve run")

        while True:
            off = memory_helpers.read_ptr_sz(mu, ptr, self.__ptr_sz)
            param = memory_helpers.read_utf8(mu, off)
            if (len(param) == 0):
                break
            params.append(param)
            ptr += self.__emu.ptr_size
        logging.warning("execve %s %r"%(filename, params))
        cmd = " ".join(params)

        pkg_name = self.__cfg.pkg.pkg_name
        pm = "pm path %s"%(pkg_name,)
        if(cmd.find(pm) > -1):
            output = "package:/data/app/%s-1.apk"%pkg_name
            logging.debug("write to stdout [%s]", output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)
        elif(cmd.find('wm density') > -1):
            output = "Physical density: 420"
            logging.info("write to stdout [%s]", output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)
        elif(cmd.find('wm size') > -1):
            output = "Physical size: 1080x1920"
            logging.info("write to stdout [%s]", output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)
        elif (cmd.find('adbd') > -1):
            output = ""
            logging.info("write to stdout [%s]", output)
            os.write(1, output.encode("utf-8"))
            sys.exit(0)

        else:
            raise NotImplementedError()
    
    def _clone(self, mu, flags, child_stack, parent_tid, new_tls, child_tid):

        #6.0 clone thread CLONE_FILES| CLONE_FS | CLONE_VM| CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID
        if (flags & FORK_FLAGS == FORK_FLAGS or 
            flags & VFORK_FLAGS == VFORK_FLAGS):
            #fork or vfork
            #0x01200011 is fork flag
            #clone(0x01200011, 0x00000000, 0x00000000, 0x00000000, 0x00000008)
            logging.warning("syscall clone do fork...")
            return self._fork(mu)
    
        elif(flags & THREAD_FLAGS == THREAD_FLAGS):
            #clone一定要成功， 4.4 的libc有bug，当clone失败之后会释放一个锁，而锁的内存在child_stack中，而他逻辑先释放了stack再unlock锁，必蹦，之所以不出问题的原因是在真机上clone不会失败，这里注意
            #父线程调用clone，返回子线程tid

            tls_ptr = 0
            if (flags & (THREAD_TLS_INIT_FLAGS) != 0):
                tls_ptr = new_tls
            tid = self.__sch.add_sub_task(child_stack, tls_ptr)
            logging.debug("clone thread call in parent thread return child thread tid [%d] child_stack [0x%08X] tls_ptr [0x%08X]"%(tid, child_stack, tls_ptr))

            #let the child thread run first

            self.__sch.yield_task()
            #6.0的libc使用这几个参数设置tid，而不使用返回值，这跟4.4的libc实现不同，两个都要兼容

            if (flags & (PARENT_SETUP_TID_FLAGS) != 0):
                mu.mem_write(parent_tid, tid.to_bytes(4, byteorder='little'))

            if (flags & (CHILD_SETUP_TID_FLAGS) != 0):
                mu.mem_write(child_tid, tid.to_bytes(4, byteorder='little'))

            if (flags & CLONE_CHILD_CLEARTID):
                #save the child_tid ptr
                self.__tid_2_tid_addr[tid] = child_tid
            
            return tid

        raise NotImplementedError("clone flags 0x%08X no suppport"%flags)
        return -1

    def _futex(self, mu, uaddr, op, val, timeout_ptr, uaddr2, val3):
        """
        See: https://linux.die.net/man/2/futex
        """

        #uaddr 是u32指针，所以指向的大小恒为4
        v = mu.mem_read(uaddr, 4)
        v = int.from_bytes(v, byteorder='little', signed=False)

        cmd = op & FUTEX_CMD_MASK
        sch = self.__emu.scheduler
        if cmd == FUTEX_WAIT or cmd == FUTEX_WAIT_BITSET:

            #TODO implement timeout
            logging.info("futext_wait call op=0x%08X uaddr=0x%08X *uaddr=0x%08X val=0x%08X timeout=0x%08X"%(op, uaddr, v, val, timeout_ptr))

            if v == val:
                timeout = -1
                if (timeout_ptr):
                    req_tv_sec = memory_helpers.read_ptr_sz(mu, timeout_ptr, self.__ptr_sz)
                    req_tv_nsec = memory_helpers.read_ptr_sz(mu, timeout_ptr + self.__ptr_sz, self.__ptr_sz)
                    ms = req_tv_sec * 1000 + req_tv_nsec / 1000000
                    timeout = ms
                    #TODO The timeout here should return -1 and ETIMEOUT. It cannot return here; the scheduler needs to determine if a timeout has occurred by specifying r0 and set_errno.
                    # This is not yet implemented; it's currently hardcoded to return 0.
                    logging.warning("futex timeout %d ms is set, the return value is 0 not matter if it expired!!!"%ms)

                sch.futex_wait(uaddr, timeout)

            return 0
        
        elif cmd == FUTEX_WAKE or cmd == FUTEX_WAKE_BITSET:
            logging.debug("futex_wake call op=0x%08X uaddr=0x%08X val=0x%08X"%(op, uaddr, val))
            assert val <= 0x7fffffff, "futex wake val=0x%08X bigger than int max!!!"%val
            nwake = 0
            for i in range(0, val):
                wake_ok = sch.futex_wake(uaddr)
                if not wake_ok:
                    break
                nwake = nwake+1

            if nwake > 0:
                # Relinquishing execution control is only to accommodate certain shared objects (SOs), such as certain dependencies (DYs), that experience infinite loops.
                # This is because UC has a bug in its support for timeouts and cannot currently support time-slice scheduling.
                sch.yield_task()

            return nwake
        elif cmd == FUTEX_FD:
            raise NotImplementedError()
        elif cmd == FUTEX_REQUEUE:
            raise NotImplementedError()
        elif cmd == FUTEX_CMP_REQUEUE:
            raise NotImplementedError()
        else:
            raise NotImplementedError()
        return 0
