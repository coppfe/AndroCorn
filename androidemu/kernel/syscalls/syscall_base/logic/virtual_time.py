import logging

from .....const.linux import *

from unicorn import Uc
from unicorn.arm_const import *

from .....utils.memory import memory_helpers

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator

class VirtualTimeSyscall:
    def __init__(self, emulator: 'Emulator'):
        self.__emu = emulator
        self.__ptr_sz = emulator.ptr_size
        self.__time_manager = emulator.time_manager

    def _gettimeofday(self, mu: 'Uc', tv_ptr, tz_ptr):
        if tv_ptr != 0:
            sec, usec = self.__time_manager.get_timeofday()
            
            mu.mem_write(tv_ptr, int(sec).to_bytes(self.__ptr_sz, byteorder='little'))
            mu.mem_write(tv_ptr + self.__ptr_sz, int(usec).to_bytes(self.__ptr_sz, byteorder='little'))

        if tz_ptr != 0:
            # timezone: minuteswest, dsttime
            mu.mem_write(tz_ptr, int(-120).to_bytes(4, byteorder='little', signed=True))
            mu.mem_write(tz_ptr + 4, int(0).to_bytes(4, byteorder='little'))

        return 0
    
    def _clock_gettime(self, mu: 'Uc', clk_id, tp_ptr):
        if tp_ptr == 0:
            return -1 # EFAULT

        if clk_id == CLOCK_REALTIME:
            sec, usec = self.__time_manager.get_timeofday()
            nsec = usec * 1000
        elif clk_id in (CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME):
            sec, nsec = self.__time_manager.get_clock_monotonic()
        else:
            logging.warning(f"Unsupported clk_id: {clk_id}")
            sec, nsec = self.__time_manager.get_clock_monotonic()
            
        mu.mem_write(tp_ptr, int(sec).to_bytes(self.__ptr_sz, byteorder='little'))
        mu.mem_write(tp_ptr + self.__ptr_sz, int(nsec).to_bytes(self.__ptr_sz, byteorder='little'))
        return 0
    
    def _nanosleep(self, mu, req, rem):
        '''
        int nanosleep(const struct timespec *req,struct timespec *rem);
        '''
        req_tv_sec = memory_helpers.read_ptr_sz(mu, req, self.__ptr_sz)
        req_tv_nsec = memory_helpers.read_ptr_sz(mu, req + self.__ptr_sz, self.__ptr_sz)
        
        ms = (req_tv_sec * 1000) + (req_tv_nsec / 1000000.0)
        
        if ms <= 0: 
            ms = 0.001

        # print(f"nanosleep called: req={req_tv_sec}s {req_tv_nsec}ns -> sleep {ms} ms")
        
        self.__emu.scheduler.sleep(ms)
        
        if rem != 0:
            memory_helpers.write_ptrs_sz(mu, rem, 0, self.__ptr_sz)
            memory_helpers.write_ptrs_sz(mu, rem + self.__ptr_sz, 0, self.__ptr_sz)

        return 0