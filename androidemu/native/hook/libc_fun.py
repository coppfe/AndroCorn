from .base import HookAddress

from typing import TYPE_CHECKING

import logging
from unicorn.arm_const import *

from unicorn import *

if TYPE_CHECKING:
    from ...emulator import Emulator

logger = logging.getLogger(__name__)

class LibCFunHooks(HookAddress):

    def __init__(self, emu: 'Emulator'):
        super().__init__(emu)

        self._emu: 'Emulator' = emu
        
        self._func_table = [
            # ("__libc_write_log", 2, self.libc_log, None)
            ("malloc", 1, self.hook_malloc, None)
        ] # name, num_args, before, after
        # not used anymore. All logs coming into writev syscall as logcat

        for hook in self._func_table:
            self.global_func_table.append(hook)
    
    def hook_malloc(self, emu, size):
        if size > 128:
            print(f"[*] Malloc: {size}")