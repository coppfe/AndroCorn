import logging
import os

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from .interrupt import InterruptHandler
from ..objects.syscall import SyscallHandler
from ..const import emu_const

from typing import TYPE_CHECKING, Dict
if TYPE_CHECKING:
    from ..scheduler import Scheduler

class SyscallHandlers:

    """
    :type interrupt_handler InterruptHandler
    """
    def __init__(self, mu, schduler, arch):
        self._handlers: Dict['SyscallHandler'] = dict()
        self.__sch: 'Scheduler' = schduler
        self.__interrupt_handler: 'InterruptHandler' = InterruptHandler(mu)
        if (arch == emu_const.ARCH_ARM32):
            self.__interrupt_handler.set_handler(2, self._handle_syscall)
        else:
            #arm64
            self.__interrupt_handler.set_handler(2, self._handle_syscall64)

    def set_handler(self, idx, name, arg_count, callback):
        self._handlers[idx] = SyscallHandler(idx, name, arg_count, callback)

    def _handle_syscall(self, mu: 'Uc'):
        idx = mu.reg_read(UC_ARM_REG_R7)
        lr = mu.reg_read(UC_ARM_REG_LR)
        tid = self.__sch.get_current_tid()

        logging.debug("%d syscall %d lr=%#010x", tid, idx, lr)

        if idx in self._handlers:
            handler = self._handlers[idx]

            args = [mu.reg_read(UC_ARM_REG_R0 + i) for i in range(handler.arg_count)]

            if logging.root.level <= logging.DEBUG:
                args_fmt = ", ".join("%#x" % a for a in args)
                pc = mu.reg_read(UC_ARM_REG_PC)
                logging.debug("%d Executing %s(%s) at %#x from %#x", 
                              tid, handler.name, args_fmt, pc, lr)
            
            try:
                result = handler.callback(mu, *args)
            except Exception:
                logging.exception("%d Error in syscall %#x handler (%s)", tid, idx, handler.name)
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM_REG_R0, result)
                if logging.root.level <= logging.DEBUG:
                    logging.debug("%d syscall %s returned %#x", tid, handler.name, result)
        else:
            pc = mu.reg_read(UC_ARM_REG_PC)
            all_args = [mu.reg_read(reg) for reg in range(UC_ARM_REG_R0, UC_ARM_REG_R7)]
            args_fmt = ", ".join("%#x" % a for a in all_args)
            
            error = "%d Unhandled syscall %#x at %#x, args(%s)" % (tid, idx, pc, args_fmt)
            logging.error(error)
            mu.emu_stop()
            raise RuntimeError(error)

    def _handle_syscall64(self, mu: 'Uc'):
        idx = mu.reg_read(UC_ARM64_REG_X8)
        lr = mu.reg_read(UC_ARM64_REG_LR)
        tid = self.__sch.get_current_tid()

        logging.debug("%d syscall %d lr=%#018x", tid, idx, lr)

        if idx in self._handlers:
            handler = self._handlers[idx]
            
            args = [mu.reg_read(UC_ARM64_REG_X0 + i) for i in range(handler.arg_count)]

            if logging.root.level <= logging.DEBUG:
                args_fmt = ", ".join("%#x" % a for a in args)
                pc = mu.reg_read(UC_ARM64_REG_PC)
                logging.debug("%d Executing %s(%s) at %#018x", tid, handler.name, args_fmt, pc)

            try:
                result = handler.callback(mu, *args)
            except Exception:
                logging.exception("%d Error in syscall %#x handler (%s)", tid, idx, handler.name)
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM64_REG_X0, result)
        else:
            pc = mu.reg_read(UC_ARM64_REG_PC)
            all_args = [mu.reg_read(UC_ARM64_REG_X0 + i) for i in range(8)]
            args_fmt = ", ".join("%#x" % a for a in all_args)
            
            error = "%d Unhandled syscall %#x at %#018x, args(%s)" % (tid, idx, pc, args_fmt)
            logging.error(error)
            mu.emu_stop()
            raise RuntimeError(error)