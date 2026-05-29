import logging
import struct

from unicorn import Uc

from ....utils.memory import helpers

from ....const.linux import *

from ....types import ptr_t

from .helpers.execve import ExecveHandler
from .helpers.process_helper import ProcessHelper
from .helpers.process_io_helper import ProcessIOHelper

from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from androidemu.arguments.process import ProcessArgumentsBlock
    from androidemu.data.states.process import ProcessState
    from androidemu.data.config import Config


class ProcessSyscalls:
    def __init__(self, process: 'ProcessArgumentsBlock', system_properties: Dict, config: 'Config'):
        pcb = process.control_block
        scheduler = process.scheduler
        ctx = process.ctx

        self._proc = ProcessHelper(scheduler)
        self._io = ProcessIOHelper(pcb)

        self._ctx: 'ProcessState' = ctx
        
        self._execve_cb = ExecveHandler(pcb, system_properties, config, process.ctx)

        self._ptr_size = ptr_t.size

        self._sch = scheduler
        self._pcb = pcb

        self._tid_map = {}

    # =========================================================
    # BASIC INFO
    # =========================================================

    def _getpid(self, mu):  return self._ctx.pid
    def _getppid(self, mu): return self._ctx.ppid
    def _getuid(self, mu):  return self._ctx.uid
    def _gettid(self, mu):  return self._ctx.current_tid
    def _geteuid(self, mu): return 0
    
    def _getresuid32(self, mu: 'Uc', ruid_ptr, euid_ptr, suid_ptr):
        uid = self._ctx.uid
        data = struct.pack("<I", uid)
        try:
            mu.mem_write(ruid_ptr, data)
            mu.mem_write(euid_ptr, data)
            mu.mem_write(suid_ptr, data)
            return 0
        except Exception as e:
            return -EFAULT
        
    def _ptrace(self, mu, request, pid, addr, data):
        ctx: 'ProcessState' = self._ctx
        if request == PTRACE_TRACEME:
            if ctx.ptrace == pid or ctx.ptrace == True:
                return 0
            else:
                return -EPERM
        elif request == PTRACE_DETACH:
            ctx.ptrace = 0
            return 0

    # =========================================================
    # PIPE
    # =========================================================

    def _pipe(self, mu, ptr):
        return self._io._pipe_common(mu, ptr, 0)

    def _pipe2(self, mu, ptr, flags):
        return self._io._pipe_common(mu, ptr, flags)

    # =========================================================
    # FORK / CLONE
    # =========================================================

    def _fork(self, mu):
        return self._proc._do_fork(mu)

    def _vfork(self, mu):
        return self._proc._do_fork(mu)

    def _clone(self, mu, flags, stack, ptid, tls, ctid):
        return self._proc._clone(mu, flags, stack, ptid, tls, ctid)

    # =========================================================
    # EXIT / WAIT
    # =========================================================

    def _exit(self, mu: Uc, code):
        tid = self._ctx.current_tid

        # futex cleanup
        if tid in self._tid_map:
            addr = self._tid_map.pop(tid)
            self._sch.futex_wake(addr)

        self._sch.exit_current_task()
        return 0

    def _wait4(self, mu, pid, status, options, rusage):
        assert rusage == 0
        return self._sch.wait4_task(pid, status, options)

    # =========================================================
    # EXECVE
    # =========================================================

    def _execve(self, mu: Uc, filename_ptr, argv_ptr, envp_ptr):
        filename = helpers.read_utf8(mu, filename_ptr)

        argv = []
        ptr = argv_ptr

        while True:
            off = helpers.read_ptr_sz(mu, ptr)
            if not off:
                break
            argv.append(helpers.read_utf8(mu, off))
            ptr += self._ptr_size

        res = self._execve_cb.execute(filename, argv)

        logging.debug("execve %s -> exit current task", filename)
        self._sch.exit_current_task()

        return res

    # =========================================================
    # DUP
    # =========================================================

    def _dup3(self, mu, oldfd, newfd, flags):
        if oldfd == newfd:
            return -EINVAL

        vfs = self._pcb.virtual_files

        old = vfs.get_fd_detail(oldfd)
        if not old:
            return -EBADF

        if vfs.has_fd(newfd):
            vfs.remove_fd(newfd)

        vfs._fds[newfd] = old
        old.ref_count += 1

        logging.debug("dup3 %d -> %d", oldfd, newfd)
        return 0

    # =========================================================
    # TID ADDRESS
    # =========================================================

    def _set_tid_address(self, mu, addr):
        tid = self._ctx.current_tid

        if addr:
            self._tid_map[tid] = addr
        else:
            self._tid_map.pop(tid, None)

        return tid

    # =========================================================
    # FUTEX (CLEANED)
    # =========================================================

    def _futex(self, mu: 'Uc', uaddr, op, val, timeout_ptr, uaddr2, val3):
        cmd = op & FUTEX_CMD_MASK
        sch = self._sch

        value = int.from_bytes(mu.mem_read(uaddr, 4), "little")

        # -------------------------
        # WAIT
        # -------------------------
        if cmd in (FUTEX_WAIT, FUTEX_WAIT_BITSET):
            if value == val:
                timeout = -1

                if timeout_ptr:
                    ptr_sz = self._ptr_size
                    sec = helpers.read_ptr_sz(mu, timeout_ptr, ptr_sz)
                    nsec = helpers.read_ptr_sz(mu, timeout_ptr + ptr_sz, ptr_sz)
                    timeout = int(sec * 1000 + nsec / 1_000_000)

                sch.futex_wait(uaddr, timeout)

            return 0

        # -------------------------
        # WAKE
        # -------------------------
        if cmd in (FUTEX_WAKE, FUTEX_WAKE_BITSET):
            count = 0

            for _ in range(val):
                if not sch.futex_wake(uaddr):
                    break
                count += 1

            if count:
                sch.yield_task()

            return count

        # -------------------------
        # NOT IMPLEMENTED
        # -------------------------
        raise NotImplementedError("futex cmd=%#x", cmd)
