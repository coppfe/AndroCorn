import struct
from typing import TYPE_CHECKING

from ....const.linux import *
from ....types import ptr_t
from ....utils.memory import helpers
from .helpers.execve import ExecveHandler
from .helpers.process_helper import ProcessHelper
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

    def _getresuid32(self, emu: 'Emulator', ruid_ptr, euid_ptr, suid_ptr):
        uid = emu.pcb.uid
        mu = emu.mu

        data = struct.pack("<I", uid)
        try:
            mu.mem_write(ruid_ptr, data)
            mu.mem_write(euid_ptr, data)
            mu.mem_write(suid_ptr, data)
            return 0
        except Exception:
            return -EFAULT

    def _ptrace(self, emu: 'Emulator', request, pid, addr, data):
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
    
        emu.mu.mem_write(files_ptr, int(fd0).to_bytes(4, byteorder='little'))
        emu.mu.mem_write(files_ptr + 4, int(fd1).to_bytes(4, byteorder='little'))
        return 0
    
    def _pipe(self, emu: 'Emulator', ptr):
        return self._pipe_common(emu, ptr, 0)

    def _pipe2(self, emu: 'Emulator', ptr, flags):
        return self._pipe_common(emu, ptr, flags)

    def _fork(self, emu: 'Emulator'):
        return self._proc._do_fork(emu.scheduler)

    def _vfork(self, emu: 'Emulator'):
        return self._proc._do_fork(emu.scheduler)

    def _clone(self, emu: 'Emulator', flags, stack, ptid, tls, ctid):
        return self._proc._clone(emu, flags, stack, ptid, tls, ctid)

    def _exit(self, emu: 'Emulator', code):
        tid = emu.pcb.current_tid
        if tid in self._tid_map:
            addr = self._tid_map.pop(tid)
            emu.scheduler.futex_wake(addr)
        emu.scheduler.exit_current_task()
        return 0

    def _wait4(self, emu: 'Emulator', pid, status, options, rusage):
        return emu.scheduler.wait4_task(pid, status, options)

    def _execve(self, emu: 'Emulator', filename_ptr, argv_ptr, envp_ptr):
        filename = helpers.read_utf8(emu.mu, filename_ptr)
        argv = []
        ptr = argv_ptr

        while True:
            off = helpers.read_ptr_sz(emu.mu, ptr)
            if not off:
                break
            argv.append(helpers.read_utf8(emu.mu, off))
            ptr += self._ptr_size

        res = self._execve_cb.execute(emu, filename, argv)
        emu.scheduler.exit_current_task()
        return res

    def _dup3(self, emu: 'Emulator', oldfd, newfd, flags):
        if oldfd == newfd:
            return -EINVAL

        old_handle = emu.vfs.get_handle(oldfd)
        if not old_handle:
            return -EBADF

        emu.vfs.close(newfd)
        emu.vfs.create_fd_for_node(old_handle.node, flags=old_handle.flags, specific_fd=newfd)
        return 0

    def _set_tid_address(self, emu: 'Emulator', addr):
        tid = emu.pcb.current_tid
        if addr:
            self._tid_map[tid] = addr
        else:
            self._tid_map.pop(tid, None)
        return tid

    def _futex(self, emu: 'Emulator', uaddr, op, val, timeout_ptr, uaddr2, val3):
        cmd = op & FUTEX_CMD_MASK
        sch = emu.scheduler
        mu = emu.mu

        value = int.from_bytes(mu.mem_read(uaddr, 4), "little")
        
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