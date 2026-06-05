import logging
import sys

from unicorn import Uc

from ....types import ptr_t
from ....utils.memory import helpers

from ....data.mem_map import STOP_MEMORY_BASE

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.core.state._global import GlobalContextMachine
    from androidemu.data.states.process import ProcessState
    from androidemu import Emulator

class SignalSyscalls:

    def __init__(self, emulator: 'Emulator', ctx: 'GlobalContextMachine'):
        self._emulator = emulator
        self._ctx: 'ProcessState' = ctx
        self._ptr_sz = ptr_t.size

        self._sigreturn_address = STOP_MEMORY_BASE + 0x1000

        if not hasattr(self._ctx, 'sigactions'):
            self._ctx.sigactions = {}

    def _deliver_signal(self, mu: Uc, sig: int) -> bool:
        if sig in self._ctx.sigactions:
            handler, mask, flags, rest = self._ctx.sigactions[sig]
            
            if handler == 1: # SIG_IGN
                logging.debug("Signal %d is ignored (SIG_IGN)", sig)
                return True
                
            elif handler > 1:
                tid = self._ctx.current_tid
                
                scheduler = self._emulator.scheduler
                task = scheduler._tasks_map[tid]
                
                logging.info("Redirecting TID %d to signal handler 0x%x", tid, handler)
                
                task.saved_signal_context = mu.context_save()
                
                regs = self._emulator.registers
                
                altstack_val = getattr(self._ctx, 'altstack', (0, 2, 0))
                alt_sp, alt_flags, alt_size = altstack_val if altstack_val is not None else (0, 2, 0)
                if alt_sp != 0:
                    new_sp = alt_sp + alt_size
                else:
                    new_sp = mu.reg_read(regs.sp) - 0x1000
                
                mu.reg_write(regs.sp, new_sp)
                mu.reg_write(regs.pc, handler)
                mu.reg_write(regs.any_0, sig)
                mu.reg_write(regs.lr, self._sigreturn_address)
                
                return True
        return False

    # =========================================================
    # KILL / TGKILL
    # =========================================================

    def _kill(self, mu: Uc, pid: int, sig: int):
        logging.debug("kill pid=%d sig=%d", pid, sig)

        if pid == self._ctx.pid:
            if self._deliver_signal(mu, sig):
                return 0

            logging.error("self-kill detected (anti-debug?) and no handler registered")
            sys.exit(-10)

        return 0

    def _tgkill(self, mu: Uc, tgid: int, tid: int, sig: int):
        logging.debug("tgkill tgid=%d tid=%d sig=%d", tgid, tid, sig)

        if tgid == self._ctx.pid:
            if sig == 6:  # SIGABRT
                raise RuntimeError("abort signal!!!")
            
            if self._deliver_signal(mu, sig):
                return 0
            
        return 0

    # =========================================================
    # SIGACTION
    # =========================================================

    def _sigaction(self, mu: Uc, sig: int, act: int, oact: int):
        if oact != 0 and sig in self._ctx.sigactions:
            old_handler, old_mask, old_flags, old_rest = self._ctx.sigactions[sig]
            if self._ptr_sz == 4:
                mu.mem_write(oact, old_handler.to_bytes(4, 'little'))
                mu.mem_write(oact + 4, old_mask.to_bytes(4, 'little'))
                mu.mem_write(oact + 8, old_flags.to_bytes(4, 'little'))
                mu.mem_write(oact + 12, old_rest.to_bytes(4, 'little'))
            else:
                mu.mem_write(oact, old_handler.to_bytes(8, 'little'))
                mu.mem_write(oact + 8, old_mask.to_bytes(8, 'little'))
                mu.mem_write(oact + 16, old_flags.to_bytes(8, 'little'))
                mu.mem_write(oact + 24, old_rest.to_bytes(8, 'little'))

        handler = helpers.read_ptr_sz(mu, act)
        mask = helpers.read_ptr_sz(mu, act + self._ptr_sz)
        flags = helpers.read_ptr_sz(mu, act + 2 * self._ptr_sz)
        rest = helpers.read_ptr_sz(mu, act + 3 * self._ptr_sz)

        self._ctx.sigactions[sig] = (handler, mask, flags, rest)

        logging.debug("sigaction sig=%d handler=0x%x flags=0x%x", sig, handler, flags)
        return 0

    # =========================================================
    # RT_SIGACTION
    # =========================================================

    def _rt_sigaction(self, mu: Uc, sig: int, act: int, oact: int, sigsetsize: int):
        if oact != 0 and sig in self._ctx.sigactions:
            old_handler, old_mask, old_flags, old_rest = self._ctx.sigactions[sig]
            if self._ptr_sz == 4:
                mu.mem_write(oact, old_handler.to_bytes(4, 'little'))
                mu.mem_write(oact + 4, old_mask.to_bytes(sigsetsize, 'little') if isinstance(old_mask, int) else bytes(sigsetsize))
                mu.mem_write(oact + 4 + sigsetsize, old_flags.to_bytes(4, 'little'))
                mu.mem_write(oact + 4 + sigsetsize + 4, old_rest.to_bytes(4, 'little'))
            else:
                mu.mem_write(oact, old_handler.to_bytes(8, 'little'))
                mu.mem_write(oact + 8, old_mask.to_bytes(sigsetsize, 'little') if isinstance(old_mask, int) else bytes(sigsetsize))
                mu.mem_write(oact + 8 + sigsetsize, old_flags.to_bytes(8, 'little'))
                mu.mem_write(oact + 8 + sigsetsize + 8, old_rest.to_bytes(8, 'little'))

        handler = helpers.read_ptr_sz(mu, act)
        mask = helpers.read_ptr_sz(mu, act + self._ptr_sz)
        flags = helpers.read_ptr_sz(mu, act + self._ptr_sz + sigsetsize)
        rest = helpers.read_ptr_sz(mu, act + self._ptr_sz + sigsetsize + self._ptr_sz)

        self._ctx.sigactions[sig] = (handler, mask, flags, rest)

        logging.debug("rt_sigaction sig=%d handler=0x%x flags=0x%x", sig, handler, flags)
        return 0

    # =========================================================
    # MASK OPS
    # =========================================================

    def _sigprocmask(self, mu: Uc, how: int, set: int, oset: int):
        return 0

    def _rt_sigprocmask(self, mu: Uc, how: int, set: int, oset: int, sigsetsize: int):
        return 0

    # =========================================================
    # ALTSTACK
    # =========================================================

    def _sigaltstack(self, mu: Uc, uss: int, ouss: int):
        logging.debug("sigaltstack uss=0x%x ouss=0x%x", uss, ouss)

        if uss != 0:
            ss_sp = helpers.read_ptr_sz(mu, uss)
            ss_flags = helpers.read_ptr_sz(mu, uss + self._ptr_sz)
            ss_size = helpers.read_ptr_sz(mu, uss + 2 * self._ptr_sz)
            
            self._ctx.altstack = (ss_sp, ss_flags, ss_size)
            logging.debug("sigaltstack configured: sp=0x%x flags=%d size=%d", ss_sp, ss_flags, ss_size)

        if ouss != 0:
            old_sp, old_flags, old_size = getattr(self._ctx, 'altstack', (0, 2, 0))
            if self._ptr_sz == 4:
                mu.mem_write(ouss, old_sp.to_bytes(4, 'little'))
                mu.mem_write(ouss + 4, old_flags.to_bytes(4, 'little'))
                mu.mem_write(ouss + 8, old_size.to_bytes(4, 'little'))
            else:
                mu.mem_write(ouss, old_sp.to_bytes(8, 'little'))
                mu.mem_write(ouss + 8, old_flags.to_bytes(8, 'little'))
                mu.mem_write(ouss + 16, old_size.to_bytes(8, 'little'))

        return 0