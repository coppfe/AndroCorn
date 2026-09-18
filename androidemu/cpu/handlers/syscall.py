import logging
from typing import TYPE_CHECKING, Dict

from ..svchandler import SyscallHandler
from .interrupt import InterruptHandler

if TYPE_CHECKING:
    from androidemu import Emulator


class SyscallsHandler:
    """
    Handler for system calls via SVC/software interrupts
    """

    FILTER = ["read", "lseek"]  # filter shit

    def __init__(self, emulator: "Emulator"):
        self._handlers: Dict[int, "SyscallHandler"] = dict()

        self.__interrupt_handler: "InterruptHandler" = InterruptHandler(emulator)

        self.__interrupt_handler.set_handler(2, self._handle_syscall)

    def set_handler(self, idx: int, name: str, arg_count: int, callback):
        self._handlers[idx] = SyscallHandler(idx, name, arg_count, callback)

    def _handle_syscall(self, emu: "Emulator"):
        regs = emu.registers

        idx = regs.v_syscall
        lr = regs.v_lr

        if idx in self._handlers:
            handler = self._handlers[idx]
            cnt = handler.arg_count

            args = regs.read_syscall_args(cnt)

            if logging.root.level <= logging.DEBUG:
                args_fmt = ", ".join("%#x" % a for a in args)
                pc = regs.v_pc

                if handler.name not in self.FILTER:
                    logging.debug(
                        "Executing %s(%s) at %#x from %#x",
                        handler.name,
                        args_fmt,
                        pc,
                        lr,
                    )

            try:
                result = handler.callback(emu, *args)

            except Exception:
                logging.exception(
                    "Error in syscall %#x handler (%s)", idx, handler.name
                )
                emu.mu.emu_stop()
                raise

            if result is not None:
                regs.v_ret = result

                if logging.root.level <= logging.DEBUG:
                    if handler.name not in self.FILTER:
                        logging.debug("syscall %s returned %#x", handler.name, result)

        else:
            pc = regs.v_pc
            all_args = [getattr(regs, f"v_reg_{i}") for i in range(8)]
            args_fmt = ", ".join("%#x" % a for a in all_args)

            error = "Unhandled syscall %#x at %#x, args(%s)" % (idx, pc, args_fmt)

            logging.error(error)
            emu.mu.emu_stop()
            raise RuntimeError(error)