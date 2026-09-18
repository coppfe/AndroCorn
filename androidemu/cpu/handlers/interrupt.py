import logging
import traceback
import inspect
import os

from unicorn import UC_HOOK_INTR

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu import Emulator

logger = logging.getLogger(__name__)


class InterruptHandler:
    """
    Interrupter for any type interrupt
    """
    def __init__(self, emulator: 'Emulator'):
        self._emu = emulator
        self._emu.mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc, intno, data):
        try:
            if intno in self._handlers:
                self._handlers[intno](self._emu) # handle_syscall
            else:
                logging.error(f"Undefined interrupt {hex(intno)}!!!")
                traceback.print_stack()
                frame = inspect.currentframe()
                traceback.format_stack(frame)
                os._exit(-1)
                
        except Exception as e:
            # traceback.print_exc()
            raise

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
