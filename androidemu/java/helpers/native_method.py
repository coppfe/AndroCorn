import inspect
import traceback
import os

from unicorn import Uc
from unicorn.arm_const import *
from unicorn.arm64_const import *
from ...const import emu_const

from ..java_class_def import JavaClassDef
from ..constants.jni_const import JNI_ERR
from ..jni_ref import jobject


def native_write_args(emu, *argv):
    if emu.arch == emu_const.ARCH_ARM32:
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        sp_reg = UC_ARM_REG_SP
    else:
        regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        sp_reg = UC_ARM64_REG_SP

    max_regs_args = len(regs)
    ptr_sz = emu.ptr_size
    amount = len(argv)
    
    nreg = min(amount, max_regs_args)
    for i in range(nreg):
        native_write_arg_register(emu, regs[i], argv[i])
    
    if amount > max_regs_args:
        sp_start = emu.mu.reg_read(sp_reg)
        stack_args_count = amount - max_regs_args
        sp_new = sp_start - (ptr_sz * stack_args_count)
        
        sp_new &= ~0xf 
        
        curr_sp = sp_new
        for arg in argv[max_regs_args:]:
            val = native_translate_arg(emu, arg)
            emu.mu.mem_write(curr_sp, val.to_bytes(ptr_sz, byteorder='little'))
            curr_sp += ptr_sz

        emu.mu.reg_write(sp_reg, sp_new)


def native_read_args_in_hook_code(emu, args_count):
    max_regs_args = 4   #寄存器参数个数
    reg_base = UC_ARM_REG_R0
    sp_reg = UC_ARM_REG_SP

    if (emu.arch == emu_const.ARCH_ARM64):
        max_regs_args = 8
        reg_base = UC_ARM64_REG_X0
        sp_reg = UC_ARM64_REG_SP
    #
    ptr_sz = emu.ptr_size

    nreg = max_regs_args
    if (args_count < max_regs_args):
        nreg = args_count
    #
    native_args = []
    mu = emu.mu

    for i in range(0, nreg):
        native_args.append(mu.reg_read(reg_base+i))
    #
    if args_count > max_regs_args:
        sp = mu.reg_read(sp_reg)

        for x in range(0, args_count - max_regs_args):
            native_args.append(int.from_bytes(mu.mem_read(sp + (x * ptr_sz), ptr_sz), byteorder='little'))
        #
    #
    return native_args
#


def native_translate_arg(emu, val):
    if isinstance(val, int):
        return val
    elif isinstance(val, bytearray):
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(type(val), JavaClassDef):
        # TODO: Look into this, seems wrong..
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(val, JavaClassDef):
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    else:
        raise NotImplementedError("Unable to write response '%s' type '%s' to emulator.", str(val), type(val))


def native_write_arg_register(emu, reg, val):
    emu.mu.reg_write(reg, native_translate_arg(emu, val))


def native_method(func):
    args = inspect.getfullargspec(func).args
    args_count = len(args) - (2 if 'self' in args else 1)

    if args_count < 0:
        raise RuntimeError("NativeMethod accept at least (self, mu) or (mu).")

    def native_method_wrapper(*argv):
        emu = argv[1] if len(argv) >= 2 else argv[0]
        mu = emu.mu

        native_args = native_read_args_in_hook_code(emu, args_count)

        try:
            if len(argv) == 1:
                result = func(mu, *native_args)
            else:
                result = func(argv[0], mu, *native_args)
        except Exception:
            traceback.print_exc()
            os._exit(1)

        ret_reg0 = UC_ARM_REG_R0
        ret_reg1 = UC_ARM_REG_R1

        if emu.arch == emu_const.ARCH_ARM64:
            ret_reg0 = UC_ARM64_REG_X0
            ret_reg1 = UC_ARM64_REG_X1

        if result is not None:
            if isinstance(result, tuple):
                native_write_arg_register(emu, ret_reg0, result[0])
                native_write_arg_register(emu, ret_reg1, result[1])
            else:
                native_write_arg_register(emu, ret_reg0, result)

    return native_method_wrapper