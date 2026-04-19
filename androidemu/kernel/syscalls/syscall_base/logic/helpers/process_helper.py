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
        # Mention: In some cases os.fork is not even needed, you can just stub it if you want
        # return -1

        logging.debug("fork called")
        r = self.__emu.scheduler.fork_task() # fake fork
        return r
    
        # if not hasattr(os, "fork"):
        #     logging.warning("Proxy call 'do_fork' is not support on Windows!!!")
        #     return -1
        # r = os.fork()
        # if (r == 0):
        #     # TODO make logic?
        #     return 0
        # else:
        #     logging.debug("-----here is parent process child pid=%d"%r)
        # return r