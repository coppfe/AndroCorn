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

class ProcessHelper:
    def __init__(self, emulator: 'Emulator'):
        self.__emu = emulator
        self.__pcb = emulator.pcb

    def _do_fork(self, mu: 'Uc'):
        logging.debug("fork called")
        if not hasattr(os, "fork"):
            logging.warning("Proxy call 'do_fork' is not support on Windows!!!")
            return -1
        r = os.fork()
        if (r == 0):
            # TODO make logic?
            return 0
        else:
            logging.debug("-----here is parent process child pid=%d"%r)
        return r