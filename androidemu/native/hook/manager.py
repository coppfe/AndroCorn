from typing import TYPE_CHECKING, Callable, Optional
import logging

from .hooks.inline import InlineHook
from .hooks.watchpoint import MemoryWatchpoint

if TYPE_CHECKING:
    from ...core import Emulator

logger = logging.getLogger(__name__)


class HookManager:
    def __init__(self, emu: 'Emulator'):
        self._emu = emu
        self._inline_engine = InlineHook(emu)
        self._watchpoint_engine = MemoryWatchpoint(emu)

    def stub(self, symname: str, callback: Callable):
        """Replaces an exported or imported function with a Python callback."""
        func_addr = self._emu._hooker.write_function(callback)
        self._emu.linker.add_symbol_hook(symname, func_addr)
        logger.debug("Stubbed %s -> %#x", symname, func_addr)

    def inline(
        self,
        addr: int,
        num_args: int,
        cb_before: Optional[Callable] = None,
        cb_after: Optional[Callable] = None
    ):
        """Hooks execution at a specific address (function prologue/epilogue)."""
        self._inline_engine.add(addr, num_args, cb_before, cb_after)

    def inline_symbol(
        self,
        module_name: str,
        symbol_name: str,
        num_args: int,
        cb_before: Optional[Callable] = None,
        cb_after: Optional[Callable] = None
    ):
        """Finds symbol in module and inline-hooks it."""
        mod = self._emu.get_library(module_name)
        if not mod:
            raise RuntimeError(f"Module '{module_name}' is not loaded!")
        addr = mod.find_symbol(symbol_name)
        if addr is None:
            raise RuntimeError(f"Symbol '{symbol_name}' not found in '{module_name}'!")
        self.inline(addr, num_args, cb_before, cb_after)

    def watch(
        self,
        addr: int,
        size: int,
        tag: str = "WATCH",
        on_read: Optional[Callable] = None,
        on_write: Optional[Callable] = None
    ):
        """Watches memory reads/writes in a given range."""
        self._watchpoint_engine.add(addr, size, tag, on_read, on_write)