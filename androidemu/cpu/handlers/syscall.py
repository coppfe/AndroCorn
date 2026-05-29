import logging
from typing import TYPE_CHECKING, Dict


from unicorn import *

from ...native.helpers.args import read_args_syscall

from ...objects.syscall import SyscallHandler
from .interrupt import InterruptHandler

if TYPE_CHECKING:
    from androidemu.objects.registers import RegistersMapping
    from unicorn import Uc


class SyscallsHandler:
    """
    :type interrupt_handler InterruptHandler
    """

    def __init__(self, mu: "Uc", registers: "RegistersMapping"):
        self._handlers: Dict[int, "SyscallHandler"] = dict()
        self._registers = registers

        self.__interrupt_handler: "InterruptHandler" = InterruptHandler(mu)

        self.__interrupt_handler.set_handler(2, self._handle_syscall)

    def set_handler(self, idx, name, arg_count, callback):
        self._handlers[idx] = SyscallHandler(idx, name, arg_count, callback)

    def _handle_syscall(self, mu: "Uc"):
        idx = mu.reg_read(self._registers.syscall)
        lr = mu.reg_read(self._registers.lr)

        # logging.debug("syscall %d lr=%#x", idx, lr)
        if idx in self._handlers:
            handler = self._handlers[idx]

            cnt = handler.arg_count
            
            args = read_args_syscall(mu, cnt, self._registers, mu._arch)

            if logging.root.level <= logging.DEBUG:
                args_fmt = ", ".join("%#x" % a for a in args)
                pc = mu.reg_read(self._registers.pc)

                if handler.name != "read":
                    logging.debug(
                        "Executing %s(%s) at %#x from %#x",
                        handler.name,
                        args_fmt,
                        pc,
                        lr,
                    )

            try:
                result = handler.callback(mu, *args)

            except Exception:
                logging.exception(
                    "Error in syscall %#x handler (%s)", idx, handler.name
                )
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(self._registers.ret, result)

                if logging.root.level <= logging.DEBUG and handler.name not in (
                    "read",
                    "lseek",
                ):
                    logging.debug("syscall %s returned %#x", handler.name, result)

        else:
            pc = mu.reg_read(self._registers.pc)

            all_args = [mu.reg_read(self._registers.any_0 + i) for i in range(8)]

            args_fmt = ", ".join("%#x" % a for a in all_args)

            error = "Unhandled syscall %#x at %#x, args(%s)" % (idx, pc, args_fmt)

            logging.error(error)
            mu.emu_stop()
            raise RuntimeError(error)
