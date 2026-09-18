from typing import TYPE_CHECKING, Callable
from ..const import emu_const

if TYPE_CHECKING:
    from ..core.emulator import Emulator

Interrupt = Callable[[int, str, int, Callable[..., None]], None]

class SysInit:
    def __init__(self, emu: 'Emulator', interrupt: Interrupt):
        if emu.arch == emu_const.ARCH_ARM32:
            from .callbacks.arm32 import CallbacksARM32 as Callback
        elif emu.arch == emu_const.ARCH_ARM64:
            from .callbacks.arm64 import CallbacksARM64 as Callback
        else:
            raise RuntimeError(f"Unsupported arch: {emu.arch}")

        table = Callback(emu)
        for sysnum, meta in table._syscall_table.items():
            interrupt(sysnum, meta[0], meta[1], meta[2])