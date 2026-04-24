import logging
import sys

from unicorn import Uc

from .....utils.memory import memory_helpers


class SignalSyscalls:

    def __init__(self, emulator):
        self.__emu = emulator
        self.__pcb = emulator.pcb

        self.__ptr_sz = emulator.ptr_size
        self.__pid = emulator.pcb.pid

        self._signals = {}  # sig -> SigAction

    # =========================================================
    # KILL / TGKILL
    # =========================================================

    def _kill(self, mu, pid, sig):
        logging.debug("kill pid=%d sig=%d", pid, sig)

        if pid == self.__pid:
            logging.error("self-kill detected (anti-debug?)")
            sys.exit(-10)

        return 0

    def _tgkill(self, mu, tgid, tid, sig):
        logging.debug("tgkill tgid=%d tid=%d sig=%d", tgid, tid, sig)

        if tgid == self.__pid and sig == 6:
            raise RuntimeError("abort signal")

        return 0

    # =========================================================
    # SIGACTION
    # =========================================================

    def _sigaction(self, mu: Uc, sig, act, oact):
        handler = memory_helpers.read_ptr_sz(mu, act, self.__ptr_sz)
        mask = memory_helpers.read_ptr_sz(mu, act + self.__ptr_sz, self.__ptr_sz)
        flags = memory_helpers.read_ptr_sz(mu, act + 2 * self.__ptr_sz, self.__ptr_sz)
        rest = memory_helpers.read_ptr_sz(mu, act + 3 * self.__ptr_sz, self.__ptr_sz)

        self._signals[sig] = (handler, mask, flags, rest)

        logging.debug("sigaction sig=%d handler=0x%x", sig, handler)
        return 0

    # =========================================================
    # RT_SIGACTION
    # =========================================================

    def _rt_sigaction(self, mu: Uc, sig, act, oact, sigsetsize):
        handler = memory_helpers.read_ptr_sz(mu, act, self.__ptr_sz)

        mask = memory_helpers.read_ptr_sz(
            mu,
            act + self.__ptr_sz,
            sigsetsize
        )

        flags = memory_helpers.read_ptr_sz(
            mu,
            act + self.__ptr_sz + sigsetsize,
            self.__ptr_sz
        )

        rest = memory_helpers.read_ptr_sz(
            mu,
            act + self.__ptr_sz + sigsetsize + self.__ptr_sz,
            self.__ptr_sz
        )

        self._signals[sig] = (handler, mask, flags, rest)

        logging.debug("rt_sigaction sig=%d handler=0x%x", sig, handler)
        return 0

    # =========================================================
    # MASK OPS
    # =========================================================

    def _sigprocmask(self, mu, how, set, oset):
        return 0

    def _rt_sigprocmask(self, mu, how, set, oset, sigsetsize):
        return 0

    # =========================================================
    # ALTSTACK
    # =========================================================

    def _sigaltstack(self, mu, uss, ouss):
        return 0