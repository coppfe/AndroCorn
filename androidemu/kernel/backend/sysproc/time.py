import logging

from ....const.linux import (
    CLOCK_REALTIME,
    CLOCK_MONOTONIC,
    CLOCK_MONOTONIC_COARSE,
    CLOCK_BOOTTIME,
    EPERM,
)
from ....types import ptr_t

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu import Emulator
    from androidemu.utils.memory.map import MemoryMap


class TimeSyscalls:

    def __init__(self):
        self._ptr_sz = ptr_t.size

    def _write_time_pair(self, mem: 'MemoryMap', ptr: int, sec: int, subsec: int):
        if self._ptr_sz == 4:
            mem.write_u32(ptr, int(sec))
            mem.write_u32(ptr + 4, int(subsec))
        else:
            mem.write_u64(ptr, int(sec))
            mem.write_u64(ptr + 8, int(subsec))

    def _gettimeofday(self, emu: 'Emulator', tv_ptr: int, tz_ptr: int) -> int:
        mem = emu.memory

        if tv_ptr:
            sec, usec = emu.time_manager.get_timeofday()
            self._write_time_pair(mem, tv_ptr, sec, usec)

        if tz_ptr:
            mem.write_u32(tz_ptr, (-120) & 0xFFFFFFFF)
            mem.write_u32(tz_ptr + 4, 0)

        return 0

    def _clock_gettime(self, emu: 'Emulator', clk_id: int, tp_ptr: int) -> int:
        if tp_ptr == 0:
            return -EPERM

        if clk_id == CLOCK_REALTIME:
            sec, usec = emu.time_manager.get_timeofday()
            nsec = usec * 1000
        elif clk_id in (CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME):
            sec, nsec = emu.time_manager.get_clock_monotonic()
        else:
            logging.warning("Unsupported clk_id=%d fallback monotonic", clk_id)
            sec, nsec = emu.time_manager.get_clock_monotonic()

        self._write_time_pair(emu.memory, tp_ptr, sec, nsec)
        return 0

    def _nanosleep(self, emu: 'Emulator', req: int, rem: int) -> int:
        mem = emu.memory

        sec = mem.read_ptr(req)
        nsec = mem.read_ptr(req + self._ptr_sz)

        ms = (sec * 1000) + (nsec / 1_000_000.0)
        if ms <= 0:
            ms = 0.001

        emu.scheduler.sleep(ms)

        if rem:
            mem.write_ptr(rem, 0)
            mem.write_ptr(rem + self._ptr_sz, 0)

        return 0