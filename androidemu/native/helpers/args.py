import struct

from ...const.emu_const import ARCH_ARM32

from ...java.class_def import JavaClassDef
from ...java.jni.reference import jobject

from ...types import ptr_t

from typing import TYPE_CHECKING, List, Union, Tuple, List

if TYPE_CHECKING:
    from unicorn import Uc
    from androidemu.objects.registers import RegistersMapping
    from ...java.jvm.main import JavaVM

def write_args(mu: 'Uc', java_vm: 'JavaVM', registers: 'RegistersMapping', *argv) -> None:
    '''
    JavaVM need here for translate PyObjects to Java References.
    '''
    regs = registers.arguments
    sp_reg = registers.sp

    max_regs_args = len(regs)
    ptr_sz = ptr_t.size
    amount = len(argv)

    nreg = min(amount, max_regs_args)
    for i in range(nreg):
        write_arg_register(mu, java_vm, regs[i], argv[i])

    if amount > max_regs_args:
        sp_start = mu.reg_read(sp_reg)
        stack_args_count = amount - max_regs_args
        sp_new = sp_start - (ptr_sz * stack_args_count)

        sp_new &= ~0xf

        curr_sp = sp_new
        for arg in argv[max_regs_args:]:
            val = translate_arg(java_vm, arg)
            mu.mem_write(curr_sp, val.to_bytes(ptr_sz, byteorder='little'))
            curr_sp += ptr_sz

        mu.reg_write(sp_reg, sp_new)

def read_args_syscall(mu: 'Uc', args_count: int, registers: 'RegistersMapping', arch: int) -> Tuple[int, ...]:
    '''
    For syscalls args was writed from r0 to r6 (or r7 in arch64)
    '''
    if arch == ARCH_ARM32:
        args = mu.reg_read_batch((registers.any_0, registers.any_1, registers.any_2, registers.any_3,
                                 registers.any_4, registers.any_5, registers.any_6))
    else:
        args = mu.reg_read_batch((registers.any_0, registers.any_1, registers.any_2, registers.any_3,
                                 registers.any_4, registers.any_5, registers.any_6, registers.any_7))
        
    return args[:args_count]

def read_args(mu: 'Uc', args_count: int, registers: 'RegistersMapping') -> List[int]:
    """
    Reads function arguments according to AAPCS.
    First 4 arguments are passed via registers, the rest are on the stack.
    """
    reg_set = (registers.any_0, registers.any_1, registers.any_2, registers.any_3)
    reg_args = mu.reg_read_batch(reg_set)
    
    if args_count <= 4:
        return list(reg_args[:args_count])
        
    native_args = list(reg_args)
    stack_args_count = args_count - 4
    
    total_stack_bytes = stack_args_count * ptr_t.size
    sp = mu.reg_read(registers.sp)
    
    stack_raw_bytes = mu.mem_read(sp, total_stack_bytes)
    
    fmt = f"<{'I' if ptr_t.size == 4 else 'Q'}"
    
    for x in range(stack_args_count):
        offset = x * ptr_t.size
        arg_bytes = stack_raw_bytes[offset : offset + ptr_t.size]
        native_args.append(struct.unpack(fmt, arg_bytes)[0])
        
    return native_args


def translate_arg(java_vm: 'JavaVM', val) -> Union[int, NotImplementedError]:
    if isinstance(val, int):
        return val
    elif isinstance(val, bytearray):
        return java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(type(val), JavaClassDef):
        return java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(val, JavaClassDef):
        return java_vm.jni_env.add_local_reference(jobject(val))
    else:
        raise NotImplementedError(f"Unable to write response '{val}' type '{type(val)}' to emulator.")


def write_arg_register(mu: 'Uc', java_vm: 'JavaVM', reg: int, val: int) -> None:
    mu.reg_write(reg, translate_arg(java_vm, val))