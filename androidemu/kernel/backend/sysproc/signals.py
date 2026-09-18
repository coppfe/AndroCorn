import logging

from ....types import ptr_t
from ....utils.memory import helpers

from ....data.layout import SIGRET

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.core import Emulator
    from androidemu.core.pcb import ProcessControlBlock

class SignalSyscalls:

    def __init__(self):
        # self._emulator = emulator
        # self._pcb: 'ProcessControlBlock' = pcb
        self._ptr_sz = ptr_t.size

    def _deliver_signal(self, emu: 'Emulator', sig: int) -> bool:
        pcb = emu.pcb

        if sig in pcb.sigactions:
            handler, mask, flags, rest = pcb.sigactions[sig]
            
            if handler == 1:  # SIG_IGN
                return True
                
            elif handler > 1:
                tid = pcb.current_tid
                scheduler = emu.scheduler
                task = scheduler._tasks_map[tid]
                
                task.signal_contexts.append(emu.mu.context_save())
                
                regs = emu.registers
                
                altstack_val = getattr(pcb, 'altstack', (0, 2, 0))
                alt_sp, alt_flags, alt_size = altstack_val if altstack_val is not None else (0, 2, 0)
                # new_sp = (alt_sp + alt_size) if alt_sp != 0 else (emu.mu.reg_read(regs.sp) - 0x1000)
                new_sp = (alt_sp + alt_size) if alt_sp != 0 else (regs.v_sp - 0x1000)

                regs.v_sp = new_sp
                regs.v_pc = handler
                regs.v_reg_0 = sig
                regs.v_lr = SIGRET

                return True
        return False

    # =========================================================
    # KILL / TGKILL
    # =========================================================

    def _kill(self, emu: 'Emulator', pid: int, sig: int):
        logging.debug("kill pid=%d sig=%d", pid, sig)

        if pid == emu.pcb.pid:
            if self._deliver_signal(emu, sig):
                return 0

            logging.error("self-kill detected (anti-debug?) and no handler registered")
            raise RuntimeError("Self-Kill Detected")

        return 0

    def _tgkill(self, emu: 'Emulator', tgid: int, tid: int, sig: int):
        logging.debug("tgkill tgid=%d tid=%d sig=%d", tgid, tid, sig)

        if tgid == emu.pcb.pid:
            if sig == 6:  # SIGABRT
                raise RuntimeError("abort signal!!!")
            
            if self._deliver_signal(emu, sig):
                return 0
            
        return 0

    # =========================================================
    # SIGACTION
    # =========================================================

    def _sigaction(self, emu: 'Emulator', sig: int, act: int, oact: int):
        if oact != 0 and sig in emu.pcb.sigactions:
            old_handler, old_mask, old_flags, old_rest = emu.pcb.sigactions[sig]
            if self._ptr_sz == 4:
                emu.mu.mem_write(oact, old_handler.to_bytes(4, 'little'))
                emu.mu.mem_write(oact + 4, old_mask.to_bytes(4, 'little'))
                emu.mu.mem_write(oact + 8, old_flags.to_bytes(4, 'little'))
                emu.mu.mem_write(oact + 12, old_rest.to_bytes(4, 'little'))
            else:
                emu.mu.mem_write(oact, old_handler.to_bytes(8, 'little'))
                emu.mu.mem_write(oact + 8, old_mask.to_bytes(8, 'little'))
                emu.mu.mem_write(oact + 16, old_flags.to_bytes(8, 'little'))
                emu.mu.mem_write(oact + 24, old_rest.to_bytes(8, 'little'))

        handler = helpers.read_ptr_sz(emu.mu, act)
        mask = helpers.read_ptr_sz(emu.mu, act + self._ptr_sz)
        flags = helpers.read_ptr_sz(emu.mu, act + 2 * self._ptr_sz)
        rest = helpers.read_ptr_sz(emu.mu, act + 3 * self._ptr_sz)

        emu.pcb.sigactions[sig] = (handler, mask, flags, rest)

        logging.debug("sigaction sig=%d handler=0x%x flags=0x%x", sig, handler, flags)
        return 0

    # =========================================================
    # RT_SIGACTION
    # =========================================================

    def _rt_sigaction(self, emu: 'Emulator', sig: int, act: int, oact: int, sigsetsize: int):
        if oact != 0 and sig in emu.pcb.sigactions:
            old_handler, old_mask, old_flags, old_rest = emu.pcb.sigactions[sig]
            if self._ptr_sz == 4:
                emu.mu.mem_write(oact, old_handler.to_bytes(4, 'little'))
                emu.mu.mem_write(oact + 4, old_mask.to_bytes(sigsetsize, 'little') if isinstance(old_mask, int) else bytes(sigsetsize))
                emu.mu.mem_write(oact + 4 + sigsetsize, old_flags.to_bytes(4, 'little'))
                emu.mu.mem_write(oact + 4 + sigsetsize + 4, old_rest.to_bytes(4, 'little'))
            else:
                emu.mu.mem_write(oact, old_handler.to_bytes(8, 'little'))
                emu.mu.mem_write(oact + 8, old_mask.to_bytes(sigsetsize, 'little') if isinstance(old_mask, int) else bytes(sigsetsize))
                emu.mu.mem_write(oact + 8 + sigsetsize, old_flags.to_bytes(8, 'little'))
                emu.mu.mem_write(oact + 8 + sigsetsize + 8, old_rest.to_bytes(8, 'little'))

        handler = helpers.read_ptr_sz(emu.mu, act)
        mask = helpers.read_ptr_sz(emu.mu, act + self._ptr_sz)
        flags = helpers.read_ptr_sz(emu.mu, act + self._ptr_sz + sigsetsize)
        rest = helpers.read_ptr_sz(emu.mu, act + self._ptr_sz + sigsetsize + self._ptr_sz)

        emu.pcb.sigactions[sig] = (handler, mask, flags, rest)

        logging.debug("rt_sigaction sig=%d handler=0x%x flags=0x%x", sig, handler, flags)
        return 0

    # =========================================================
    # MASK OPS
    # =========================================================

    def _sigprocmask(self, emu: 'Emulator', how: int, set: int, oset: int):
        return 0

    def _rt_sigprocmask(self, emu: 'Emulator', how: int, set: int, oset: int, sigsetsize: int):
        return 0

    # =========================================================
    # ALTSTACK
    # =========================================================

    def _sigaltstack(self, emu: 'Emulator', uss: int, ouss: int):
        logging.debug("sigaltstack uss=0x%x ouss=0x%x", uss, ouss)

        mu = emu.mu

        if uss != 0:
            ss_sp = helpers.read_ptr_sz(mu, uss)
            ss_flags = helpers.read_ptr_sz(mu, uss + self._ptr_sz)
            ss_size = helpers.read_ptr_sz(mu, uss + 2 * self._ptr_sz)
            
            emu.pcb.altstack = (ss_sp, ss_flags, ss_size)
            logging.debug("sigaltstack configured: sp=0x%x flags=%d size=%d", ss_sp, ss_flags, ss_size)

        if ouss != 0:
            old_sp, old_flags, old_size = getattr(emu.pcb, 'altstack', (0, 2, 0))
            if self._ptr_sz == 4:
                mu.mem_write(ouss, old_sp.to_bytes(4, 'little'))
                mu.mem_write(ouss + 4, old_flags.to_bytes(4, 'little'))
                mu.mem_write(ouss + 8, old_size.to_bytes(4, 'little'))
            else:
                mu.mem_write(ouss, old_sp.to_bytes(8, 'little'))
                mu.mem_write(ouss + 8, old_flags.to_bytes(8, 'little'))
                mu.mem_write(ouss + 16, old_size.to_bytes(8, 'little'))

        return 0