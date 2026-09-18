from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator


def native_method(func):
    code = func.__code__
    has_self = code.co_varnames[:1] == ('self',)
    args_count = code.co_argcount - (2 if has_self else 1)

    if has_self:
        def native_method_wrapper(self_obj, emu: 'Emulator', *argv):
            native_args = emu.registers.read_args(args_count)
            result = func(self_obj, emu, *native_args)
            if result is not None:
                if isinstance(result, tuple):
                    emu.registers.v_reg_0 = emu.registers._translate_val(emu.java_vm, result[0])
                    emu.registers.v_reg_1 = emu.registers._translate_val(emu.java_vm, result[1])
                else:
                    emu.registers.v_reg_0 = emu.registers._translate_val(emu.java_vm, result)
    else:
        def native_method_wrapper(emu: 'Emulator', *argv):
            native_args = emu.registers.read_args(args_count)
            result = func(emu, *native_args)
            if result is not None:
                if isinstance(result, tuple):
                    emu.registers.v_reg_0 = emu.registers._translate_val(emu.java_vm, result[0])
                    emu.registers.v_reg_1 = emu.registers._translate_val(emu.java_vm, result[1])
                else:
                    emu.registers.v_reg_0 = emu.registers._translate_val(emu.java_vm, result)

    return native_method_wrapper