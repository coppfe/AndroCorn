from ..const import emu_const

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from androidemu.arguments.system import SystemArgumentsBlock
    from androidemu.arguments.process import ProcessArgumentsBlock

Interrupt = Callable[[int, str, int, Callable[..., None]], None]

class SysInit:
    def __init__(self, process: 'ProcessArgumentsBlock', system: 'SystemArgumentsBlock', interrupt: Interrupt):
        if system.arch == emu_const.ARCH_ARM32:
            from .callbacks.arm32 import CallbacksARM32 as Callback
        elif system.arch == emu_const.ARCH_ARM64:
            from .callbacks.arm64 import CallbacksARM64 as Callback
        else:
            raise RuntimeError(f"Arch is not arm32 or arm64")
        _table = Callback(process, system)
        _entries = _table._syscall_table

        _table._fs_helper._clear_proc_dir()
        process.control_block.virtual_files.attach_generator(_table._generator)
        
        for sysnum in _entries.keys():
            meta = _entries.get(sysnum)
                             #string  #int     #callable
            interrupt(sysnum, meta[0], meta[1], meta[2])