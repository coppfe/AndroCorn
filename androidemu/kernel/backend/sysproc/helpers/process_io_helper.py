import logging
import os
from random import randint

from unicorn import Uc
from unicorn.arm_const import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.core.process.pcb import ProcessControlBlock

class ProcessIOHelper:
    def __init__(self, pcb: 'ProcessControlBlock') -> None:
        self._pcb = pcb
    
    def _pipe_common(self, mu: 'Uc', files_ptr: int, flags: int):
        if (hasattr(os, "pipe2")):
            ps = os.pipe2(flags)
        else:
            logging.warning("'pipe2' not support. Using 'pipe'")
            ps = os.pipe()
        logging.debug("pipe return %r"%(ps,))

        self._pcb.virtual_files.add_fd("[pipe_r]", "[pipe_r]", ps[0])
        self._pcb.virtual_files.add_fd("[pipe_w]", "[pipe_w]", ps[1])

        # files_ptr in 32 and 64 arch is `int` list so 4 bytes isn't problem.

        mu.mem_write(files_ptr, int(ps[0]).to_bytes(4, byteorder='little'))
        mu.mem_write(files_ptr+4, int(ps[1]).to_bytes(4, byteorder='little'))
        return 0