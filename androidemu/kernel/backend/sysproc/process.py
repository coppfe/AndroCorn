from typing import TYPE_CHECKING

from ....const.linux import *
from ....types import ptr_t
from .helpers.execve import ExecveHandler
from .helpers.process_helper import ProcessHelper
from ....utils.memory import helpers
from ...fs.nodes.devices import VirtualPipe, PipeReadNode, PipeWriteNode

if TYPE_CHECKING:
    from androidemu.core import Emulator


class ProcessSyscalls:
    def __init__(self):
        self._ptr_size = ptr_t.size
        self._proc = ProcessHelper()
        self._execve_cb = ExecveHandler()
        self._tid_map = {}

    def _getpid(self,  emu: 'Emulator'):  return emu.pcb.pid
    def _getppid(self, emu: 'Emulator'):  return emu.pcb.ppid
    def _getuid(self,  emu: 'Emulator'):  return emu.pcb.uid
    def _gettid(self,  emu: 'Emulator'):  return emu.pcb.current_tid
    def _geteuid(self, emu: 'Emulator'):  return 0

    def _getresuid32(self, emu: 'Emulator', ruid_ptr: int, euid_ptr: int, suid_ptr: int) -> int:
        uid = emu.pcb.uid
        mem = emu.memory
        try:
            mem.write_u32(ruid_ptr, uid)
            mem.write_u32(euid_ptr, uid)
            mem.write_u32(suid_ptr, uid)
            return 0
        except Exception:
            return -EFAULT

    def _ptrace(self, emu: 'Emulator', request: int, pid: int, addr: int, data: int) -> int:
        if request == PTRACE_TRACEME:
            return 0 if (emu.pcb.ptrace == pid or emu.pcb.ptrace is True) else -EPERM
        elif request == PTRACE_DETACH:
            emu.pcb.ptrace = 0
            return 0
        return -EPERM

    def _pipe_common(self, emu: 'Emulator', files_ptr: int, flags: int) -> int:
        pipe = VirtualPipe()
        fd0 = emu.vfs.create_fd_for_node(PipeReadNode(pipe))
        fd1 = emu.vfs.create_fd_for_node(PipeWriteNode(pipe))

        emu.memory.write_u32(files_ptr, fd0)
        emu.memory.write_u32(files_ptr + 4, fd1)
        return 0

    def _pipe(self, emu: 'Emulator', ptr: int) -> int:
        return self._pipe_common(emu, ptr, 0)

    def _pipe2(self, emu: 'Emulator', ptr: int, flags: int) -> int:
        return self._pipe_common(emu, ptr, flags)

    def _fork(self, emu: 'Emulator'):
        return self._proc._do_fork(emu.scheduler)

    def _vfork(self, emu: 'Emulator'):
        return self._proc._do_fork(emu.scheduler)

    def _clone(self, emu: 'Emulator', flags: int, stack: int, ptid: int, tls: int, ctid: int):
        return self._proc._clone(emu, flags, stack, ptid, tls, ctid)

    def _exit(self, emu: 'Emulator', code: int) -> int:
        tid = emu.pcb.current_tid
        if tid in self._tid_map:
            addr = self._tid_map.pop(tid)
            emu.scheduler.futex_wake(addr)
        emu.scheduler.exit_current_task()
        return 0

    def _wait4(self, emu: 'Emulator', pid: int, status: int, options: int, rusage: int) -> int:
        return emu.scheduler.wait4_task(pid, status, options)

    def _execve(self, emu: 'Emulator', filename_ptr: int, argv_ptr: int, envp_ptr: int) -> int:
        mem = emu.memory
        filename = helpers.read_utf8(mem, filename_ptr)
        argv = []
        ptr = argv_ptr

        while True:
            off = mem.read_ptr(ptr)
            if not off:
                break
            argv.append(helpers.read_utf8(mem, off))
            ptr += self._ptr_size

        res = self._execve_cb.execute(emu, filename, argv)
        emu.scheduler.exit_current_task()
        return res

    def _dup3(self, emu: 'Emulator', oldfd: int, newfd: int, flags: int) -> int:
        if oldfd == newfd:
            return -EINVAL

        old_handle = emu.vfs.get_handle(oldfd)
        if not old_handle:
            return -EBADF

        emu.vfs.close(newfd)
        emu.vfs.create_fd_for_node(old_handle.node, flags=old_handle.flags, specific_fd=newfd)
        return 0

    def _set_tid_address(self, emu: 'Emulator', addr: int) -> int:
        tid = emu.pcb.current_tid
        if addr:
            self._tid_map[tid] = addr
        else:
            self._tid_map.pop(tid, None)
        return tid

    def _futex(self, emu: 'Emulator', uaddr: int, op: int, val: int, timeout_ptr: int, uaddr2: int, val3: int) -> int:
        if not uaddr:
            return -EFAULT

        cmd = op & FUTEX_CMD_MASK
        sch = emu.scheduler
        mem = emu.memory

        if cmd in (FUTEX_WAIT, FUTEX_WAIT_BITSET):
            try:
                value = mem.read_u32(uaddr)
            except Exception:
                return -EFAULT

            if value == val:
                timeout = -1
                if timeout_ptr:
                    sec = mem.read_ptr(timeout_ptr)
                    nsec = mem.read_ptr(timeout_ptr + self._ptr_size)
                    timeout = int(sec * 1000 + nsec / 1_000_000)
                sch.futex_wait(uaddr, timeout)
            return 0

        if cmd in (FUTEX_WAKE, FUTEX_WAKE_BITSET):
            count = 0
            for _ in range(val):
                if not sch.futex_wake(uaddr):
                    break
                count += 1
            if count:
                sch.yield_task()
            return count

        raise NotImplementedError(f"futex cmd={cmd:#x}")