import logging
import os
import sys

from unicorn import Uc
from unicorn.arm_const import *

from .....const.android import *
from .....const.linux import *
from .....const import emu_const
from .....const.metatags import *
from .....utils.memory import memory_helpers
from .helpers.execve import ExecveHandler

from .helpers.process_helper import ProcessHelper
from .helpers.process_io_helper import ProcessIOHelper

from ....flags import (
    CLONE_PARENT_SETTID,
    CLONE_CHILD_SETTID,
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
        self.__handle_execve: 'ExecveHandler' = ExecveHandler(emulator)

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
        return self.__emu.pcb.pid
    
    def _getuid(self, mu):
        return self.__emu.pcb.uid
    
    def _gettid(self, mu):
        return self.__emu.scheduler.get_current_tid()
    
    def _ptrace(self, mu, request, pid, addr, data):
        logging.debug("skip syscall ptrace request [%d] pid [0x%x] addr [0x%08X] data [0x%08X]"%(request, pid, addr, data))
        return 0
    
    def _ARM_set_tls(self, mu, tls_ptr):
        assert self.__emu.arch == emu_const.ARCH_ARM32, "error only arm32 has _ARM_set_tls syscall!!!"
        self.__emu.tls_utils.set_tls(tls_ptr)

    def _ARM_cacheflush(self, mu):
        return 0

    def _dup3(self, mu, oldfd, newfd, flags):
        if oldfd == newfd:
            return -22 # EINVAL

        vfs = self.__pcb.virtual_files
        
        old_vf = vfs.get_fd_detail(oldfd)
        if not old_vf:
            logging.error("dup3: oldfd %d not found", oldfd)
            return -9 # EBADF

        if vfs.has_fd(newfd):
            vfs.remove_fd(newfd)

        vfs._fds[newfd] = old_vf
        old_vf.ref_count += 1
        
        logging.debug("dup3: mapped guest fd %d -> %d (ref_count: {%d})", oldfd, newfd, old_vf.ref_count)
        
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
        t = self.__sch.wait4_task(pid, wstatus, options)
        return t

    def _exit(self, mu: 'Uc', err_code):
        sch = self.__emu.scheduler
        cur_tid = sch.get_current_tid()
        err_code = 0

        if (cur_tid in self.__tid_2_tid_addr):
            tid_addr_futex = self.__tid_2_tid_addr[cur_tid]
            sch.futex_wake(tid_addr_futex)

            mu.mem_write(tid_addr_futex, int(0).to_bytes(4, byteorder='little'))
            self.__tid_2_tid_addr.pop(cur_tid)
    
        sch.exit_current_task()
        return err_code
    
    def _execve(self, mu: 'Uc', filename_ptr: int, argv_ptr: int, envp_ptr: int):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        ptr = argv_ptr
        params = []

        while True:
            off = memory_helpers.read_ptr_sz(mu, ptr, self.__emu.ptr_size)
            if off == 0:
                break
            param = memory_helpers.read_utf8(mu, off)
            params.append(param)
            ptr += self.__emu.ptr_size

        res = self.__handle_execve.execute(filename, params)
        
        # TODO: Implement -1 and -2 code exit

        logging.debug("Execve handled for %s, terminating child task.", filename)
        self.__emu.scheduler.exit_current_task() # actually it works so why not
        
        return res
    
    def _clone(self, mu: 'Uc', flags, child_stack, parent_tid, new_tls, child_tid):
        if (flags & FORK_FLAGS == FORK_FLAGS or flags & VFORK_FLAGS == VFORK_FLAGS):
            logging.debug("Interpreting clone as virtual fork...")

            tid = self.__proxy._do_fork(mu)
            # if tid == -1:
            #     return -1
            
            if (flags & CLONE_PARENT_SETTID):
                if parent_tid != 0:
                    mu.mem_write(parent_tid, tid.to_bytes(4, byteorder='little'))
                else:
                    logging.warning("[!] CLONE_PARENT_SETTID set but parent_tid is NULL")

            if (flags & CLONE_CHILD_SETTID):
                if child_tid != 0:
                    mu.mem_write(child_tid, tid.to_bytes(4, byteorder='little'))
                else:
                    logging.warning("[!] CLONE_CHILD_SETTID set but child_tid is NULL")

            return tid

        elif (flags & THREAD_FLAGS == THREAD_FLAGS):
            tls_ptr = new_tls if (flags & THREAD_TLS_INIT_FLAGS) else 0
            
            tid = self.__sch.add_sub_task(child_stack, tls_ptr)
            
            logging.debug("Clone thread: tid=%d, stack=%#x, tls=%#x", tid, child_stack, tls_ptr)

            self.__sch.yield_task()

            if (flags & PARENT_SETUP_TID_FLAGS):
                mu.mem_write(parent_tid, tid.to_bytes(4, byteorder='little'))
            if (flags & CHILD_SETUP_TID_FLAGS):
                mu.mem_write(child_tid, tid.to_bytes(4, byteorder='little'))
            if (flags & CLONE_CHILD_CLEARTID):
                self.__tid_2_tid_addr[tid] = child_tid
                
            return tid

        raise NotImplementedError("Clone flags 0x%08X not supported", flags)

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
