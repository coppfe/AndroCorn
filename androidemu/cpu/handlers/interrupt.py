import logging
import traceback
import inspect
import os

from unicorn import *

logger = logging.getLogger(__name__)


class InterruptHandler:
    """
    Interrupter for any type interrupt
    """
    def __init__(self, mu: 'Uc'):
        self._mu = mu
        self._mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc, intno, data):
        try:
            if intno in self._handlers:
                self._handlers[intno](uc)
            else:
                logging.error(f"Undefined interrupt {hex(intno)}!!!")
                traceback.print_stack()
                frame = inspect.currentframe()
                traceback.format_stack(frame)
                os._exit(-1)
                
        except Exception as e:
            traceback.print_exc()
            os._exit(-1)

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
