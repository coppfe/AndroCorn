import logging
from typing import TYPE_CHECKING

from ....data.layout import SIGRET
from ....types import ptr_t

if TYPE_CHECKING:
    from androidemu.core import Emulator


class SignalSyscalls:

    def __init__(self):
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
                new_sp = (alt_sp + alt_size) if alt_sp != 0 else (regs.v_sp - 0x1000)

                regs.v_sp = new_sp
                regs.v_pc = handler
                regs.v_reg_0 = sig
                regs.v_lr = SIGRET

                return True
        return False

    def _kill(self, emu: 'Emulator', pid: int, sig: int) -> int:
        logging.debug("kill pid=%d sig=%d", pid, sig)

        if pid == emu.pcb.pid:
            if self._deliver_signal(emu, sig):
                return 0

            logging.error("self-kill detected (anti-debug?) and no handler registered")
            raise RuntimeError("Self-Kill Detected")

        return 0

    def _tgkill(self, emu: 'Emulator', tgid: int, tid: int, sig: int) -> int:
        logging.debug("tgkill tgid=%d tid=%d sig=%d", tgid, tid, sig)

        if tgid == emu.pcb.pid:
            if sig == 6:  # SIGABRT
                raise RuntimeError("abort signal!!!")

            if self._deliver_signal(emu, sig):
                return 0

        return 0

    def _sigaction(self, emu: 'Emulator', sig: int, act: int, oact: int) -> int:
        mem = emu.memory
        ptr_sz = self._ptr_sz

        if oact != 0 and sig in emu.pcb.sigactions:
            old_handler, old_mask, old_flags, old_rest = emu.pcb.sigactions[sig]
            mem.write_ptr(oact, old_handler)
            mem.write_ptr(oact + ptr_sz, old_mask if isinstance(old_mask, int) else 0)
            mem.write_ptr(oact + 2 * ptr_sz, old_flags)
            mem.write_ptr(oact + 3 * ptr_sz, old_rest)

        if act != 0:
            handler = mem.read_ptr(act)
            mask = mem.read_ptr(act + ptr_sz)
            flags = mem.read_ptr(act + 2 * ptr_sz)
            rest = mem.read_ptr(act + 3 * ptr_sz)

            emu.pcb.sigactions[sig] = (handler, mask, flags, rest)
            logging.debug("sigaction sig=%d handler=0x%x flags=0x%x", sig, handler, flags)

        return 0
    
    def _rt_sigaction(self, emu: 'Emulator', sig: int, act: int, oact: int, sigsetsize: int) -> int:
        mem = emu.memory
        ptr_sz = self._ptr_sz

        if oact != 0 and sig in emu.pcb.sigactions:
            old_handler, old_mask, old_flags, old_rest = emu.pcb.sigactions[sig]
            mem.write_ptr(oact, old_handler)

            if isinstance(old_mask, int):
                if sigsetsize <= ptr_sz:
                    mem.write_ptr(oact + ptr_sz, old_mask)
                else:
                    mem.write_bytes(oact + ptr_sz, old_mask.to_bytes(sigsetsize, 'little'))
            else:
                mem.write_bytes(oact + ptr_sz, bytes(sigsetsize))

            mem.write_ptr(oact + ptr_sz + sigsetsize, old_flags)
            mem.write_ptr(oact + ptr_sz + sigsetsize + ptr_sz, old_rest)

        if act != 0:
            handler = mem.read_ptr(act)
            mask = mem.read_ptr(act + ptr_sz)
            flags = mem.read_ptr(act + ptr_sz + sigsetsize)
            rest = mem.read_ptr(act + ptr_sz + sigsetsize + ptr_sz)

            emu.pcb.sigactions[sig] = (handler, mask, flags, rest)
            logging.debug("rt_sigaction sig=%d handler=0x%x flags=0x%x", sig, handler, flags)

        return 0

    def _sigprocmask(self, emu: 'Emulator', how: int, set_ptr: int, oset_ptr: int) -> int:
        return 0

    def _rt_sigprocmask(self, emu: 'Emulator', how: int, set_ptr: int, oset_ptr: int, sigsetsize: int) -> int:
        return 0

    def _sigaltstack(self, emu: 'Emulator', uss: int, ouss: int) -> int:
        logging.debug("sigaltstack uss=0x%x ouss=0x%x", uss, ouss)
        mem = emu.memory
        ptr_sz = self._ptr_sz

        if uss != 0:
            ss_sp = mem.read_ptr(uss)
            ss_flags = mem.read_ptr(uss + ptr_sz)
            ss_size = mem.read_ptr(uss + 2 * ptr_sz)

            emu.pcb.altstack = (ss_sp, ss_flags, ss_size)
            logging.debug("sigaltstack configured: sp=0x%x flags=%d size=%d", ss_sp, ss_flags, ss_size)

        if ouss != 0:
            old_sp, old_flags, old_size = getattr(emu.pcb, 'altstack', (0, 2, 0))
            mem.write_ptr(ouss, old_sp)
            mem.write_ptr(ouss + ptr_sz, old_flags)
            mem.write_ptr(ouss + 2 * ptr_sz, old_size)

        return 0