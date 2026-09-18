import logging
import struct

from ....const.linux import *
from ....utils.memory import helpers

from ....types import ptr_t

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc
    from androidemu import Emulator

# =========================================================
# TIME SYSCALLS
# =========================================================

class TimeSyscalls:

    def __init__(self):
        self._ptr_sz = ptr_t.size

    # =========================================================
    # INTERNAL HELPERS
    # =========================================================

    def _write_time_pair(self, mu: 'Uc', ptr, sec, subsec):
        fmt = "<II" if self._ptr_sz == 4 else "<QQ"
        data = struct.pack(fmt, int(sec), int(subsec))
        mu.mem_write(ptr, data)

    # =========================================================
    # GETTIMEOFDAY
    # =========================================================

    def _gettimeofday(self, emu: 'Emulator', tv_ptr, tz_ptr):
        if tv_ptr:
            sec, usec = emu.time_manager.get_timeofday()
            self._write_time_pair(emu.mu, tv_ptr, sec, usec)

        if tz_ptr:
            emu.mu.mem_write(tz_ptr, (-120).to_bytes(4, "little", signed=True))
            emu.mu.mem_write(tz_ptr + 4, (0).to_bytes(4, "little"))

        return 0

    # =========================================================
    # CLOCK_GETTIME
    # =========================================================

    def _clock_gettime(self, emu: 'Emulator', clk_id, tp_ptr):
        if tp_ptr == 0:
            return -EPERM

        if clk_id == CLOCK_REALTIME:
            sec, usec = emu.time_manager.get_timeofday()
            nsec = usec * 1000

        elif clk_id in (
            CLOCK_MONOTONIC,
            CLOCK_MONOTONIC_COARSE,
            CLOCK_BOOTTIME
        ):
            sec, nsec = emu.time_manager.get_clock_monotonic()

        else:
            logging.warning("Unsupported clk_id=%d fallback monotonic", clk_id)
            sec, nsec = emu.time_manager.get_clock_monotonic()

        self._write_time_pair(emu.mu, tp_ptr, sec, nsec)
        return 0

    # =========================================================
    # NANOSLEEP
    # =========================================================

    def _nanosleep(self, emu: 'Emulator', req, rem):
        sec = helpers.read_ptr_sz(emu.mu, req)
        nsec = helpers.read_ptr_sz(emu.mu, req + self._ptr_sz)

        ms = (sec * 1000) + (nsec / 1_000_000.0)

        if ms <= 0:
            ms = 0.001

        emu.scheduler.sleep(ms)

        if rem:
            helpers.write_uints(emu.mu, rem, 0)
            helpers.write_uints(emu.mu, rem + self._ptr_sz, 0)

        return 0