import logging
import time
import os

from unicorn import Uc
from unicorn.arm_const import *

import random

from .....const.android import *
from .....const.linux import *
from .....const import emu_const
from .....const.metatags import *
from .....utils.memory import memory_helpers
from .helpers.prctl import PrctlHandler

from unicorn import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator

class SystemSyscalls:
    def __init__(self, emulator: 'Emulator'):

        cfg = emulator.config

        self.__emu: 'Emulator' = emulator

        self.__device_cfg = cfg.pkg.device
        self.__kernel_cfg = self.__device_cfg.kernel
        self.__mem_cfg = self.__device_cfg.memory

        self._clock_start = time.time()
        self._clock_offset = random.randint(50000, 100000)

        self.__prctl_handler = PrctlHandler(self.__emu.mu, cfg.pkg.pkg_name, self.__emu.ptr_size)

    @PROXY
    def _prctl(self, mu, option, arg2, arg3, arg4, arg5):
        """
        int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
        See:
        - https://linux.die.net/man/2/prctl
        - https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h

        For PR_SET_VMA:
        - https://android.googlesource.com/platform/bionic/+/263325d/libc/include/sys/prctl.h
        - https://sourceforge.net/p/strace/mailman/message/34329772/
        """
        self.__prctl_handler.handle(option, arg2, arg3, arg4, arg5)

    def _getcpu(self, mu, _cpu, node, cache):
        if _cpu != 0:
            #unsigned *指针，写4没问题
            mu.mem_write(_cpu, int(1).to_bytes(4, byteorder='little'))
        return 0
    
    def _getrandom(self, mu, buf_addr, count, flags):
        """
        size_t getrandom(void *buf, size_t buflen, unsigned int flags);
        """
        try:
            rand_bytes = os.urandom(count)
            
            mu.mem_write(buf_addr, rand_bytes)
            
            logging.debug("getrandom size=%d flags=%#x", count, flags)
            return count
        except Exception as e:
            logging.error(f"getrandom failed: {e}")
            return -1 # EFAULT

    def _uname(self, mu, buf):
        is_32 = self.__emu.arch == emu_const.ARCH_ARM32
        
        sysname = self.__kernel_cfg.sysname
        nodename = self.__kernel_cfg.nodename
        release = self.__kernel_cfg.release
        version = self.__kernel_cfg.version
        machine = "armv8l" if is_32 else "aarch64"
        domain = self.__kernel_cfg.domain

        memory_helpers.write_utf8(mu, buf + 0, sysname)
        memory_helpers.write_utf8(mu, buf + 65, nodename)
        memory_helpers.write_utf8(mu, buf + 130, release)
        memory_helpers.write_utf8(mu, buf + 195, version)
        memory_helpers.write_utf8(mu, buf + 260, machine)
        memory_helpers.write_utf8(mu, buf + 325, domain)
        
        return 0

    def _sysinfo(self, mu: 'Uc', info_ptr):
        '''
        si = {sysinfo} 
        uptime = {__kernel_long_t} 91942
        loads = {__kernel_ulong_t [3]} 
        [0] = {__kernel_ulong_t} 503328
        [1] = {__kernel_ulong_t} 504576
        [2] = {__kernel_ulong_t} 537280
        totalram = {__kernel_ulong_t} 1945137152
        freeram = {__kernel_ulong_t} 47845376
        sharedram = {__kernel_ulong_t} 0
        bufferram = {__kernel_ulong_t} 169373696
        totalswap = {__kernel_ulong_t} 0
        freeswap = {__kernel_ulong_t} 0
        procs = {__u16} 1297
        pad = {__u16} 0
        totalhigh = {__kernel_ulong_t} 1185939456
        freehigh = {__kernel_ulong_t} 1863680
        mem_unit = {__u32} 1
        f = 0 char[8]
        '''

        total_mb = self.__mem_cfg.ram_total_mb
        total_ram = total_mb * 1024 * 1024
        
        free_percent = self.__mem_cfg.ram_free_percent_start
        free_percent += (random.randint(-100, 100) / 100.0) 
        free_ram = int(total_ram * (free_percent / 100.0))
        
        uptime = int(self._clock_offset + time.time() - self._clock_start)

        mem_unit = 1024 
        total_units = total_mb * 1024
        free_units  = int(total_units * (free_percent / 100.0))

        total_ram_units = total_mb * 1024 

        # loads = [503328, 504576, 537280] # Load avg 1/5/15 min
        loads = [int(x * (0.8 + 0.4 * random.random())) for x in [503328, 504576, 537280]]

        high_limit_units = 896 * 1024
        total_high_units = (total_units - high_limit_units) if total_units > high_limit_units else 0

        if self.__emu.arch == emu_const.ARCH_ARM32:
            mu.mem_write(info_ptr + 0, int(uptime).to_bytes(4, 'little'))
            
            for i in range(3):
                mu.mem_write(info_ptr + 4 + (i*4), int(loads[i]).to_bytes(4, 'little'))
            
            mu.mem_write(info_ptr + 16, int(total_units).to_bytes(4, 'little'))
            mu.mem_write(info_ptr + 20, int(free_units).to_bytes(4, 'little'))
            mu.mem_write(info_ptr + 24, int(0).to_bytes(4, 'little'))             # shared
            mu.mem_write(info_ptr + 28, int(total_units // 20).to_bytes(4, 'little')) # buffer
            mu.mem_write(info_ptr + 32, int(0).to_bytes(4, 'little'))             # totalswap
            mu.mem_write(info_ptr + 36, int(0).to_bytes(4, 'little'))             # freeswap
            mu.mem_write(info_ptr + 40, int(random.randint(500, 1500)).to_bytes(2, 'little'))
            mu.mem_write(info_ptr + 42, int(0).to_bytes(2, 'little'))
            mu.mem_write(info_ptr + 44, int(total_high_units).to_bytes(4, 'little'))
            mu.mem_write(info_ptr + 48, int(total_high_units // 2).to_bytes(4, 'little'))
            mu.mem_write(info_ptr + 52, int(mem_unit).to_bytes(4, 'little'))
                        
        else:
            # ARM64 (Longs are 8 bytes)
            mu.mem_write(info_ptr + 0, int(uptime).to_bytes(8, 'little'))
             # Loads
            for i in range(3):
                mu.mem_write(info_ptr + 8 + (i*8), int(loads[i]).to_bytes(8, 'little'))
                
            mu.mem_write(info_ptr + 32, int(total_ram).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 40, int(free_ram).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 48, int(0).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 56, int(total_ram // 20).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 64, int(0).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 72, int(0).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 80, int(random.randint(500, 1500)).to_bytes(2, 'little'))
            mu.mem_write(info_ptr + 82, int(0).to_bytes(6, 'little')) # pad
    
            mu.mem_write(info_ptr + 88, int(0).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 96, int(0).to_bytes(8, 'little'))
            mu.mem_write(info_ptr + 104, int(mem_unit).to_bytes(4, 'little'))

        if logging.root.level <= logging.DEBUG:
            f_mb = free_ram // 1024 // 1024
            t_mb = total_ram // 1024 // 1024
            logging.debug("sysinfo: TotalRAM=%d MB FreeRAM=%d MB", t_mb, f_mb)
        return 0