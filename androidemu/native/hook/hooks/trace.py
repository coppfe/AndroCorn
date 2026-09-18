import logging
from typing import TYPE_CHECKING, Optional
from unicorn import UC_HOOK_BLOCK

if TYPE_CHECKING:
    from ....core.emulator import Emulator
    from ....internal.module import Module

logger = logging.getLogger("Tracer")


class CrossModuleTracer:
    """
    High-performance execution tracer.
    Only intercepts cross-module jumps (e.g. Target SO -> Libc / System libs).
    Uses UC_HOOK_BLOCK to avoid massive single-instruction overhead.
    """

    def __init__(self, emu: "Emulator"):
        self._emu = emu
        self._hook_handle = None
        self._current_module: Optional["Module"] = None
        self._enabled = False

    def start(self):
        if self._enabled:
            return
        self._enabled = True
        self._hook_handle = self._emu.mu.hook_add(
            UC_HOOK_BLOCK,
            self._hook_block
        )
        logger.info("[+] CrossModuleTracer enabled")

    def stop(self):
        if not self._enabled:
            return
        self._emu.mu.hook_del(self._hook_handle)
        self._enabled = False
        logger.info("[-] CrossModuleTracer disabled")

    def _find_module(self, addr: int) -> Optional["Module"]:
        for mod in self._emu.linker.modules:
            if mod.base <= addr < mod.base + mod.size:
                return mod
        return None

    def _hook_block(self, uc, address, size, user_data):
        cur = self._current_module
        if cur and (cur.base <= address < cur.base + cur.size):
            return

        new_mod = self._find_module(address)
        if new_mod and new_mod != cur:
            from_name = cur.filename.split("/")[-1] if cur else "UNKNOWN"
            to_name = new_mod.filename.split("/")[-1]

            sym_name = new_mod.find_symbol_name(address)
            offset_str = f"+{address - new_mod.base:#x}" if not sym_name else f": {sym_name}"

            lr = self._emu.registers.v_lr
            logger.warning(
                "[JUMP] %s -> %s%s (LR: %#x)",
                from_name, to_name, offset_str, lr
            )
            self._current_module = new_mod