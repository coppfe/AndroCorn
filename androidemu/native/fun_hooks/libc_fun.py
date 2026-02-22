from .base_fun import BaseFuncHooks

from typing import TYPE_CHECKING

import logging
import random
from unicorn.arm_const import *

from unicorn import *

if TYPE_CHECKING:
    from ...emulator import Emulator

logger = logging.getLogger(__name__)

class LibCFunHooks(BaseFuncHooks):

    def __init__(self, emu: 'Emulator'):
        super().__init__(emu)

        self._emu: 'Emulator' = emu
        
        self._func_table = [
            ("__libc_write_log", 2, self.libc_log, None)
        ] # name, num_args, before, after
        # idk how many args a function have
        #FIXME: num_args

        for hook in self._func_table:

            self.global_func_table.append(hook)


    def libc_log(self, uc, *args):
        print("__libc_write_log called", args)