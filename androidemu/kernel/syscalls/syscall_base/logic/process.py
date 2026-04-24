import logging

from unicorn import Uc

from .....utils.memory import memory_helpers
from .....const import emu_const
from .....const.metatags import *
from .....const.linux import *

from .helpers.execve import ExecveHandler
from .helpers.process_helper import ProcessHelper
from .helpers.process_io_helper import ProcessIOHelper

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator


class ProcessSyscalls:
    def __init__(self, emulator: 'Emulator'):
        self.__emu = emulator

        self.__proc = ProcessHelper(emulator)
        self.__io = ProcessIOHelper(emulator)
        self.__execve = ExecveHandler(emulator)

        self.__sch = emulator.scheduler
        self.__pcb = emulator.pcb

        self.__tid_map = {}

    # =========================================================
    # BASIC INFO
    # =========================================================

    def _getpid(self, mu):
        return self.__pcb.pid

    def _getuid(self, mu):
        return self.__pcb.uid

    def _gettid(self, mu):
        return self.__sch.get_current_tid()

    # =========================================================
    # PTRACE / ARM
    # =========================================================

    def _ptrace(self, mu, request, pid, addr, data):
        logging.debug("ptrace skip req=%d pid=%d", request, pid)
        return 0

    def _ARM_set_tls(self, mu, tls_ptr):
        assert self.__emu.arch == emu_const.ARCH_ARM32
        self.__emu.tls_utils.set_tls(tls_ptr)

    def _ARM_cacheflush(self, mu):
        return 0

    # =========================================================
    # PIPE
    # =========================================================

    @PROXY
    def _pipe(self, mu, ptr):
        return self.__io._pipe_common(mu, ptr, 0)

    @PROXY
    def _pipe2(self, mu, ptr, flags):
        return self.__io._pipe_common(mu, ptr, flags)

    # =========================================================
    # FORK / CLONE
    # =========================================================

    @PROXY
    def _fork(self, mu):
        return self.__proc._do_fork(mu)

    @PROXY
    def _vfork(self, mu):
        return self.__proc._do_fork(mu)

    def _clone(self, mu, flags, stack, ptid, tls, ctid):
        return self.__proc._clone(mu, flags, stack, ptid, tls, ctid)

    # =========================================================
    # EXIT / WAIT
    # =========================================================

    def _exit(self, mu: Uc, code):
        tid = self.__sch.get_current_tid()

        # futex cleanup
        if tid in self.__tid_map:
            addr = self.__tid_map.pop(tid)
            self.__sch.futex_wake(addr)

        self.__sch.exit_current_task()
        return 0

    def _wait4(self, mu, pid, status, options, rusage):
        assert rusage == 0
        return self.__sch.wait4_task(pid, status, options)

    # =========================================================
    # EXECVE
    # =========================================================

    def _execve(self, mu: Uc, filename_ptr, argv_ptr, envp_ptr):
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        argv = []
        ptr = argv_ptr

        while True:
            off = memory_helpers.read_ptr_sz(mu, ptr, self.__emu.ptr_size)
            if not off:
                break
            argv.append(memory_helpers.read_utf8(mu, off))
            ptr += self.__emu.ptr_size

        res = self.__execve.execute(filename, argv)

        logging.debug("execve %s -> exit current task", filename)
        self.__sch.exit_current_task()

        return res

    # =========================================================
    # DUP
    # =========================================================

    def _dup3(self, mu, oldfd, newfd, flags):
        if oldfd == newfd:
            return -EINVAL

        vfs = self.__pcb.virtual_files

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
        tid = self.__sch.get_current_tid()

        if addr:
            self.__tid_map[tid] = addr
        else:
            self.__tid_map.pop(tid, None)

        return tid

    # =========================================================
    # FUTEX (CLEANED)
    # =========================================================

    def _futex(self, mu, uaddr, op, val, timeout_ptr, uaddr2, val3):
        cmd = op & FUTEX_CMD_MASK
        sch = self.__sch

        value = int.from_bytes(mu.mem_read(uaddr, 4), "little")

        # -------------------------
        # WAIT
        # -------------------------
        if cmd in (FUTEX_WAIT, FUTEX_WAIT_BITSET):
            if value == val:
                timeout = -1

                if timeout_ptr:
                    ptr_sz = self.__emu.ptr_size
                    sec = memory_helpers.read_ptr_sz(mu, timeout_ptr, ptr_sz)
                    nsec = memory_helpers.read_ptr_sz(mu, timeout_ptr + ptr_sz, ptr_sz)
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