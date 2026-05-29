import inspect
import traceback
import os

from .args import read_args, write_arg_register

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator


def native_method(func):
    args = inspect.getfullargspec(func).args
    args_count = len(args) - (2 if 'self' in args else 1)

    def native_method_wrapper(*argv):
        emu: 'Emulator' = argv[1] if len(argv) >= 2 else argv[0] # for 'self'
        mu = emu.mu

        native_args = read_args(mu, args_count, emu.registers)
        
        try:
            if len(argv) == 1:
                result = func(emu, *native_args)
            else:
                result = func(argv[0], emu, *native_args)
        except Exception:
            traceback.print_exc()
            os._exit(1)

        ret_reg0 = emu.registers.any_0
        ret_reg1 = emu.registers.any_1

        if result is not None:
            if isinstance(result, tuple):
                write_arg_register(emu.mu, emu.java_vm, ret_reg0, result[0])
                write_arg_register(emu.mu, emu.java_vm, ret_reg1, result[1])
            else:
                write_arg_register(emu.mu, emu.java_vm, ret_reg0, result)

    return native_method_wrapper
