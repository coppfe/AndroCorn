import logging
from random import randint

from .....const.flags import *

from unicorn import Uc
from unicorn.arm_const import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.cpu.scheduler import Scheduler

# REMOVE PCB

class ProcessHelper:
    def __init__(self, scheduler: 'Scheduler'):
        self._scheduler = scheduler

        self._tid_2_tid_addr = {}

    def _do_fork(self, mu: 'Uc'):
        # NOTE: In some cases os.fork is not even needed, you can just stub it if you want
        # return -1
        r = self._scheduler.fork_task() # fake fork
        return r

    def _clone(self, mu: 'Uc', flags, child_stack, parent_tid, new_tls, child_tid):

        if (flags & FORK_FLAGS == FORK_FLAGS or 
            flags & VFORK_FLAGS == VFORK_FLAGS):
            #fork or vfork
            #0x01200011 is fork flag
            #clone(0x01200011, 0x00000000, 0x00000000, 0x00000000, 0x00000008)

            return self._do_fork(mu)
    
        elif(flags & THREAD_FLAGS == THREAD_FLAGS):
            tls_ptr = 0
            if (flags & (THREAD_TLS_INIT_FLAGS) != 0):
                tls_ptr = new_tls
            tid = self._scheduler.add_sub_task(child_stack, tls_ptr)
            logging.debug("clone thread call in parent thread return child thread tid [%d] child_stack [0x%08X] tls_ptr [0x%08X]"%(tid, child_stack, tls_ptr))

            if (flags & (PARENT_SETUP_TID_FLAGS) != 0):
                mu.mem_write(parent_tid, tid.to_bytes(4, byteorder='little'))

            if (flags & (CHILD_SETUP_TID_FLAGS) != 0):
                mu.mem_write(child_tid, tid.to_bytes(4, byteorder='little'))

            if (flags & CLONE_CHILD_CLEARTID):
                #save the child_tid ptr
                self._tid_2_tid_addr[tid] = child_tid
            
            self._scheduler.yield_task()

            return tid

        raise NotImplementedError("clone flags 0x%08X no suppport"%flags)
        # return -EPERM