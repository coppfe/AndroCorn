import logging
import os
import traceback
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from unicorn import UC_HOOK_CODE

from ....const import emu_const
from ....data import layout as config
from ....utils.memory.helpers import standlize_addr

if TYPE_CHECKING:
    from ....core.emulator import Emulator

logger = logging.getLogger(__name__)


class InlineHook:
    """
    Hook function entry and exit with optional argument mutation and replacement.
    """
    RET_BRIDGE_ADDR = config.STOP_MEMORY_BASE + 0x800

    def __init__(self, emu: "Emulator"):
        self._emu = emu
        self._arch = emu.arch
        self._hook_params: Dict[int, Tuple[int, Optional[Callable], Optional[Callable]]] = {}
        self._call_stack: List[Tuple[int, int, List[Any], Optional[Callable]]] = []

        nop_code = b"\x00\xF0\x20\xE3" if self._arch == emu_const.ARCH_ARM32 else b"\x1F\x20\x03\xD5"
        self._emu.mu.mem_write(self.RET_BRIDGE_ADDR, nop_code)

        self._emu.mu.hook_add(
            UC_HOOK_CODE,
            self._hook_return_bridge,
            None,
            self.RET_BRIDGE_ADDR,
            self.RET_BRIDGE_ADDR
        )

    def add(self, addr: int, num_args: int, cb_before: Optional[Callable] = None, cb_after: Optional[Callable] = None):
        addr = standlize_addr(addr)
        if addr not in self._hook_params:
            self._emu.mu.hook_add(UC_HOOK_CODE, self._hook_func_head, None, addr, addr)
        self._hook_params[addr] = (num_args, cb_before, cb_after)

    def _hook_return_bridge(self, mu, address, size, user_data):
        try:
            if not self._call_stack:
                logger.error("Return bridge hit but call stack is empty!")
                return

            orig_addr, saved_lr, saved_args, cb_after = self._call_stack.pop()
            regs = self._emu.registers
            retval = regs.v_ret

            if cb_after:
                new_ret = cb_after(self._emu, retval, *saved_args)
                if new_ret is not None:
                    regs.v_ret = new_ret

            if self._arch == emu_const.ARCH_ARM32:
                regs.set_thumb() if (saved_lr & 1) else regs.clear_thumb()
                regs.v_pc = standlize_addr(saved_lr)
            else:
                regs.v_pc = saved_lr

        except Exception:
            mu.emu_stop()
            traceback.print_exc()
            logger.exception("Error in return bridge")
            os._exit(-1)

    def _hook_func_head(self, mu, address, size, user_data):
        try:
            address = standlize_addr(address)
            if address not in self._hook_params:
                return

            nargs, cb_before, cb_after = self._hook_params[address]
            regs = self._emu.registers
            args = regs.read_args(nargs)

            if cb_before:
                res = cb_before(self._emu, *args)
                is_handled = res is True or (isinstance(res, tuple) and res[0] is True)
                if is_handled:
                    if isinstance(res, tuple):
                        regs.v_ret = res[1]

                    lr = regs.v_lr
                    if self._arch == emu_const.ARCH_ARM32:
                        regs.set_thumb() if (lr & 1) else regs.clear_thumb()
                        regs.v_pc = standlize_addr(lr)
                    else:
                        regs.v_pc = lr
                    return

            if cb_after:
                saved_lr = regs.v_lr
                self._call_stack.append((address, saved_lr, args, cb_after))
                regs.v_lr = self.RET_BRIDGE_ADDR

        except Exception:
            traceback.print_exc()
            os._exit(1)