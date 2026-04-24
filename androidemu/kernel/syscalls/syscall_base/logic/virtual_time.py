import logging

from unicorn import Uc

from .....const.linux import *
from .....utils.memory import memory_helpers

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator


# =========================================================
# TIME SYSCALLS
# =========================================================

class VirtualTimeSyscall:

    def __init__(self, emulator: 'Emulator'):
        self.__emu = emulator
        self.__tm = emulator.time_manager

        self.__ptr_sz = emulator.ptr_size

    # =========================================================
    # INTERNAL HELPERS
    # =========================================================

    def _write_time_pair(self, mu: Uc, ptr, sec, subsec):
        """
        Writes (sec, subsec) using ptr_size
        """
        mu.mem_write(ptr, int(sec).to_bytes(self.__ptr_sz, "little"))
        mu.mem_write(ptr + self.__ptr_sz, int(subsec).to_bytes(self.__ptr_sz, "little"))

    # =========================================================
    # GETTIMEOFDAY
    # =========================================================

    def _gettimeofday(self, mu: Uc, tv_ptr, tz_ptr):
        if tv_ptr:
            sec, usec = self.__tm.get_timeofday()
            self._write_time_pair(mu, tv_ptr, sec, usec)

        if tz_ptr:
            mu.mem_write(tz_ptr, (-120).to_bytes(4, "little", signed=True))
            mu.mem_write(tz_ptr + 4, (0).to_bytes(4, "little"))

        return 0

    # =========================================================
    # CLOCK_GETTIME
    # =========================================================

    def _clock_gettime(self, mu: Uc, clk_id, tp_ptr):
        if tp_ptr == 0:
            return -EPERM

        if clk_id == CLOCK_REALTIME:
            sec, usec = self.__tm.get_timeofday()
            nsec = usec * 1000

        elif clk_id in (
            CLOCK_MONOTONIC,
            CLOCK_MONOTONIC_COARSE,
            CLOCK_BOOTTIME
        ):
            sec, nsec = self.__tm.get_clock_monotonic()

        else:
            logging.warning("Unsupported clk_id=%d fallback monotonic", clk_id)
            sec, nsec = self.__tm.get_clock_monotonic()

        self._write_time_pair(mu, tp_ptr, sec, nsec)
        return 0

    # =========================================================
    # NANOSLEEP
    # =========================================================

    def _nanosleep(self, mu: Uc, req, rem):
        sec = memory_helpers.read_ptr_sz(mu, req, self.__ptr_sz)
        nsec = memory_helpers.read_ptr_sz(mu, req + self.__ptr_sz, self.__ptr_sz)

        ms = (sec * 1000) + (nsec / 1_000_000.0)

        if ms <= 0:
            ms = 0.001

        self.__emu.scheduler.sleep(ms)

        if rem:
            memory_helpers.write_ptrs_sz(mu, rem, 0, self.__ptr_sz)
            memory_helpers.write_ptrs_sz(mu, rem + self.__ptr_sz, 0, self.__ptr_sz)

        return 0