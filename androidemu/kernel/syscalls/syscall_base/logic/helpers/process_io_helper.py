import logging
import os
import ctypes
import time
import sys
import socket
from random import randint

from unicorn import Uc
from unicorn.arm_const import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ......emulator import Emulator

class ProcessIOHelper:
    def __init__(self, emulator: 'Emulator'):
        self.__emu = emulator
        self.__pcb = emulator.pcb
    
    def _pipe_common(self, mu: 'Uc', files_ptr: int, flags: int):
        if (hasattr(os, "pipe2")):
            ps = os.pipe2(flags)
        else:
            logging.warning("'pipe2' not support. Using 'pipe'")
            ps = os.pipe()
        logging.debug("pipe return %r"%(ps,))

        self.__pcb.virtual_files.add_fd("[pipe_r]", "[pipe_r]", ps[0])
        self.__pcb.virtual_files.add_fd("[pipe_w]", "[pipe_w]", ps[1])

        #files_ptr 无论32还是64 都是个int数组，因此写4没有问题

        mu.mem_write(files_ptr, int(ps[0]).to_bytes(4, byteorder='little'))
        mu.mem_write(files_ptr+4, int(ps[1]).to_bytes(4, byteorder='little'))
        return 0