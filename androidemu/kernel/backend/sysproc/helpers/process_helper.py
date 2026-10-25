import logging
from typing import TYPE_CHECKING

from .....const.flags import (
    FORK_FLAGS,
    VFORK_FLAGS,
    THREAD_FLAGS,
    THREAD_TLS_INIT_FLAGS,
    CLONE_PARENT_SETTID,
    CLONE_CHILD_SETTID,
    CLONE_CHILD_CLEARTID,
    CHILD_SETUP_TID_FLAGS,
)

if TYPE_CHECKING:
    from androidemu import Emulator
    from androidemu.cpu.scheduler import Scheduler


class ProcessHelper:
    def __init__(self):
        self._tid_2_tid_addr = {}

    def _do_fork(self, sch: 'Scheduler'):
        return sch.fork_task()

    def _clone(self, emu: 'Emulator', flags: int, child_stack: int, parent_tid: int, new_tls: int, child_tid: int) -> int:
        mem = emu.memory

        if (flags & FORK_FLAGS == FORK_FLAGS) or (flags & VFORK_FLAGS == VFORK_FLAGS):
            return self._do_fork(emu.scheduler)

        elif (flags & THREAD_FLAGS == THREAD_FLAGS):
            tls_ptr = new_tls if (flags & THREAD_TLS_INIT_FLAGS) else 0

            tid = emu.scheduler.add_sub_task(child_stack, tls_ptr)
            logging.debug(
                "clone thread return tid [%d] child_stack [0x%08X] tls_ptr [0x%08X]",
                tid, child_stack, tls_ptr
            )

            if (flags & CLONE_PARENT_SETTID) and parent_tid != 0:
                mem.write_u32(parent_tid, tid)

            if (flags & (CLONE_CHILD_SETTID | CHILD_SETUP_TID_FLAGS)) and child_tid != 0:
                mem.write_u32(child_tid, tid)

            if flags & CLONE_CHILD_CLEARTID:
                self._tid_2_tid_addr[tid] = child_tid

            emu.scheduler.yield_task()
            return tid

        raise NotImplementedError(f"clone flags 0x{flags:08X} no support")