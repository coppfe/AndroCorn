import logging
import os
import random
from typing import TYPE_CHECKING

from ....const.android import *
from ....const.linux import *
from ....const import emu_const
from .helpers.prctl import PrctlHandler

if TYPE_CHECKING:
    from androidemu import Emulator
    from androidemu.data.config import Config
    from androidemu.core.state.time_manager import TimeManager


class SystemSyscalls:

    # =========================================================
    # INIT
    # =========================================================

    def __init__(self, config: 'Config'):
        dev = config.pkg.device
        self._kernel = dev.kernel
        self._mem_cfg = dev.memory

        self._prctl_cb = PrctlHandler()

    # =========================================================
    # PRCTL
    # =========================================================

    def _prctl(self, emu: 'Emulator', option: int, arg2: int, arg3: int, arg4: int, arg5: int) -> int:
        return self._prctl_cb.handle(emu, option, arg2, arg3, arg4, arg5)

    # =========================================================
    # GETTERS
    # =========================================================

    def _getcpu(self, emu: 'Emulator', cpu_ptr: int, node_ptr: int, cache: int) -> int:
        if cpu_ptr:
            # CPU #1 по умолчанию
            emu.memory.write_u32(cpu_ptr, 1)
        return 0

    def _getrandom(self, emu: 'Emulator', buf: int, count: int, flags: int) -> int:
        try:
            data = os.urandom(count)
            emu.memory.write_bytes(buf, data)
            logging.debug("getrandom n=%d flags=%x", count, flags)
            return count
        except Exception as e:
            logging.error("getrandom failed: %s", e)
            return -EPERM

    def _getrlimit(self, emu: 'Emulator', resource: int, rlim_ptr: int) -> int:
        # struct rlimit {
        #     rlim_t rlim_cur;
        #     rlim_t rlim_max;
        # };
        mem = emu.memory
        ptr_sz = mem._ptr_sz

        # RLIMIT_STACK = 7
        if resource == 7:
            rlim_cur = 8 * 1024 * 1024  # 8MB
            rlim_max = 8 * 1024 * 1024
        else:
            rlim_cur = 1024
            rlim_max = 1024

        mem.write_ptr(rlim_ptr, rlim_cur)
        mem.write_ptr(rlim_ptr + ptr_sz, rlim_max)
        return 0

    # =========================================================
    # UNAME
    # =========================================================

    def _uname(self, emu: 'Emulator', buf: int) -> int:
        is32 = (emu.arch == emu_const.ARCH_ARM32)
        mem = emu.memory

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
            mem.write_bytes(buf + off, val.encode("utf-8") + b"\x00")

        return 0

    # =========================================================
    # SYSINFO MODEL
    # =========================================================

    def _build_sysinfo_model(self, tm: 'TimeManager'):
        total_mb = self._mem_cfg.ram_total_mb
        total_bytes = total_mb * 1024 * 1024
        mem_unit = 1024

        base_free_pct = self._mem_cfg.ram_free_percent_start
        jitter = random.uniform(-1.0, 1.0)
        free_pct = max(0.0, min(100.0, base_free_pct + jitter))
        free_bytes = int(total_bytes * (free_pct / 100.0))

        uptime, _ = tm.get_clock_monotonic()

        loads_base = (503328, 504576, 537280)
        loads = [int(x * (0.8 + random.random() * 0.4)) for x in loads_base]

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

    def _sysinfo(self, emu: 'Emulator', ptr: int) -> int:
        m = self._build_sysinfo_model(emu.time_manager)
        mem = emu.memory
        arch32 = (emu.arch == emu_const.ARCH_ARM32)

        if arch32:
            mem.write_u32(ptr, m["uptime"])

            for i, v in enumerate(m["loads"]):
                mem.write_u32(ptr + 4 + i * 4, v)

            mem.write_u32(ptr + 16, self._u32(m["total"] // 1024))
            mem.write_u32(ptr + 20, self._u32(m["free"] // 1024))
            mem.write_u32(ptr + 24, self._u32(m["shared"]))
            mem.write_u32(ptr + 28, self._u32(m["buffer"] // 1024))

            mem.write_u32(ptr + 32, self._u32(m["swap_total"]))
            mem.write_u32(ptr + 36, self._u32(m["swap_free"]))

            mem.write_u16(ptr + 40, self._u16(m["procs"]))

            mem.write_u32(ptr + 44, self._u32(m["high_total"] // 1024))
            mem.write_u32(ptr + 48, self._u32(m["high_total"] // 2048))

            mem.write_u32(ptr + 52, self._u32(m["mem_unit"]))

        else:
            mem.write_u64(ptr, m["uptime"])

            for i, v in enumerate(m["loads"]):
                mem.write_u64(ptr + 8 + i * 8, v)

            mem.write_u64(ptr + 32, m["total"])
            mem.write_u64(ptr + 40, m["free"])
            mem.write_u64(ptr + 48, m["shared"])
            mem.write_u64(ptr + 56, m["buffer"])

            mem.write_u64(ptr + 64, m["swap_total"])
            mem.write_u64(ptr + 72, m["swap_free"])

            mem.write_u16(ptr + 80, self._u16(m["procs"]))

            mem.write_u32(ptr + 104, m["mem_unit"])

        return 0

    def _swapoff(self, emu: 'Emulator', path_ptr: int) -> int:
        try:
            swap_path = emu.memory.read_utf8(path_ptr) if path_ptr else "NULL"
            logging.debug("[sys_swapoff] App tried to disable swap on: %s", swap_path)
        except Exception:
            return -EFAULT

        return -EPERM

    # =========================================================
    # UTILS
    # =========================================================
    @staticmethod
    def _u32(v: int) -> int:
        return min(v, 0xFFFFFFFF)

    @staticmethod
    def _u16(v: int) -> int:
        return min(v, 0xFFFF)