import logging
import os
import time
import random
import struct

from unicorn import Uc

from ....const.android import *
from ....const.linux import *
from ....const import emu_const
from ....utils.memory import helpers
from ...dev.prctl import PrctlHandler

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.data.config import Config
    from androidemu.data.states.system import SystemState
    from androidemu.core.state._global import GlobalContextMachine

class SystemSyscalls:

    # =========================================================
    # INIT
    # =========================================================

    def __init__(self, mu: 'Uc', config: 'Config', ctx: 'GlobalContextMachine'):
        
        self._ctx: 'SystemState' = ctx
        dev = config.pkg.device

        self._kernel = dev.kernel
        self._mem_cfg = dev.memory

        self._prctl_cb = PrctlHandler(mu, ctx)


        self._ctx.t0 = time.time()
        self._ctx.uptime_bias = random.randint(50000, 100000)

    # =========================================================
    # PRCTL
    # =========================================================

    def _prctl(self, mu, option, arg2, arg3, arg4, arg5):
        return self._prctl_cb.handle(option, arg2, arg3, arg4, arg5)

    # =========================================================
    # GETTERS
    # =========================================================

    def _getcpu(self, mu: 'Uc', cpu_ptr, node_ptr, cache):
        if cpu_ptr:
            mu.mem_write(cpu_ptr, (1).to_bytes(4, "little"))
        return 0

    def _getrandom(self, mu, buf, count, flags):
        try:
            data = os.urandom(count)
            mu.mem_write(buf, data)
            logging.debug("getrandom n=%d flags=%x", count, flags)
            return count
        except Exception as e:
            logging.error("getrandom failed: %s", e)
            return -EPERM
        
    def _getrlimit(self, mu, resource, rlim_ptr):
        # int getrlimit(int resource, struct rlimit *rlim);
        # struct rlimit {
        #     rlim_t rlim_cur;  // soft limit
        #     rlim_t rlim_max;  // hard limit
        # };

        # resource 7 = RLIMIT_STACK
        if resource == 7:
            rlim_cur = 8 * 1024 * 1024  # 8MB
            rlim_max = 8 * 1024 * 1024
        else:
            rlim_cur = 1024
            rlim_max = 1024

        data = struct.pack("<II", rlim_cur, rlim_max)

        mu.mem_write(rlim_ptr, data)
        return 0


    # =========================================================
    # UNAME
    # =========================================================

    def _uname(self, mu: 'Uc', buf):
        is32 = mu._arch == emu_const.ARCH_ARM32

        fields = [
            self._kernel.sysname,
            self._kernel.nodename,
            self._kernel.release,
            self._kernel.version,
            "armv8l" if is32 else "aarch64",
            self._kernel.domain,
        ]

        offsets = [0, 65, 130, 195, 260, 325]

        for off, val in zip(offsets, fields):
            helpers.write_utf8(mu, buf + off, val)

        return 0

    # =========================================================
    # SYSINFO MODEL
    # =========================================================

    def _build_sysinfo_model(self):
        total_mb = self._mem_cfg.ram_total_mb
        total_bytes = total_mb * 1024 * 1024

        mem_unit = 1024

        base_free_pct = self._mem_cfg.ram_free_percent_start
        jitter = random.uniform(-1.0, 1.0)
        free_pct = max(0.0, min(100.0, base_free_pct + jitter))

        free_bytes = int(total_bytes * (free_pct / 100.0))

        uptime = int(self._ctx.uptime_bias + (time.time() - self._ctx.t0))

        loads_base = (503328, 504576, 537280)
        loads = [
            int(x * (0.8 + random.random() * 0.4))
            for x in loads_base
        ]

        buffer_ram = total_bytes // 20
        shared_ram = 0
        swap_total = 0
        swap_free = 0

        procs = random.randint(500, 1500)

        high_threshold = 896 * 1024
        high_total = max(total_bytes - high_threshold, 0)

        return {
            "uptime": uptime,
            "loads": loads,

            "total": total_bytes,
            "free": free_bytes,

            "shared": shared_ram,
            "buffer": buffer_ram,

            "swap_total": swap_total,
            "swap_free": swap_free,

            "procs": procs,
            "mem_unit": mem_unit,

            "high_total": high_total,
        }

    # =========================================================
    # SYSINFO SERIALIZER
    # =========================================================

    def _sysinfo(self, mu: Uc, ptr):
        m = self._build_sysinfo_model()
        arch32 = mu._arch == emu_const.ARCH_ARM32

        def w(off, val, size):
            mu.mem_write(ptr + off, int(val).to_bytes(size, "little", signed=False))

        if arch32:
            w(0, m["uptime"], 4)

            for i, v in enumerate(m["loads"]):
                w(4 + i * 4, v, 4)

            w(16, self._u32(m["total"] // 1024), 4)
            w(20, self._u32(m["free"] // 1024), 4)
            w(24, self._u32(m["shared"]), 4)
            w(28, self._u32(m["buffer"] // 1024), 4)

            w(32, self._u32(m["swap_total"]), 4)
            w(36, self._u32(m["swap_free"]), 4)

            w(40, self._u16(m["procs"]), 2)

            w(44, self._u32(m["high_total"] // 1024), 4)
            w(48, self._u32(m["high_total"] // 2048), 4)

            w(52, self._u32(m["mem_unit"]), 4)

        else:
            w(0, m["uptime"], 8)

            for i, v in enumerate(m["loads"]):
                w(8 + i * 8, v, 8)

            w(32, m["total"], 8)
            w(40, m["free"], 8)
            w(48, m["shared"], 8)
            w(56, m["buffer"], 8)

            w(64, m["swap_total"], 8)
            w(72, m["swap_free"], 8)

            w(80, self._u16(m["procs"]), 2)

            w(104, m["mem_unit"], 4)

        return 0
    
    # =========================================================
    # UTILS
    # =========================================================
    def _u32(self, v):
        return min(v, 0xFFFFFFFF)

    def _u16(self, v):
        return min(v, 0xFFFF)