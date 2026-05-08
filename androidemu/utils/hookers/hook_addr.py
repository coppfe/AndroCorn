from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from ...const import emu_const
from ...data.mem_map import HOOK_STUB_MEMORY_SIZE
import traceback
import logging
import os
from ...native.helpers.native_method import native_write_args, native_read_args_in_hook_code

from typing import TYPE_CHECKING, Callable, Optional
if TYPE_CHECKING:
    from ...emulator import Emulator

def is_thumb(cpsr):
    return (cpsr & (1<<5)) != 0


def set_thumb(cpsr):
    return cpsr | (1<<5)


def clear_thumb(cpsr):
    return cpsr & (~(1<<5))

def standlize_addr(addr):
    return addr & (~1)


class AddressHooker:
    #32 layout
    '''
    funAddr
    ldr lr, [pc, #0x0]
    bx lr
    original lr
    '''
    #64 layout
    '''
    funcAddr
    #ldr x30, #0x8
    #br x30
    original lr
    '''
    def __hook_stub(self, mu: 'Uc', address, size, user_data):
        try:
            address = standlize_addr(address)

            fun_entry_addr = address - self.__emu.ptr_size
            fun_entry_bytes = mu.mem_read(fun_entry_addr, self.__emu.ptr_size)
            fun_entry = int.from_bytes(fun_entry_bytes, byteorder='little', signed=False)

            if (fun_entry in self.__hook_params):
                hook_param = self.__hook_params[fun_entry]
                cb_after = hook_param[2]

                r0 = 0
                r1 = 0

                if (self.__arch == emu_const.ARCH_ARM32):
                    r0 = mu.reg_read(UC_ARM_REG_R0)
                    r1 = mu.reg_read(UC_ARM_REG_R1)
                else:
                    r0 = mu.reg_read(UC_ARM64_REG_X0)
                    r1 = mu.reg_read(UC_ARM64_REG_X1)

                cb_after(self.__emu, r0, r1)

        except Exception as e:
            # Make sure we catch exceptions inside hooks and stop emulation.
            mu.emu_stop()
            traceback.print_exc()
            logging.exception("catch error on _hook")
            os._exit(-1)
            raise

    def __init__(self, emu: 'Emulator'):
        self.__emu = emu
        self.__arch = self.__emu.arch
        self.__hook_params = {}
        self.__stub_off = self.__emu.memory.map(0, HOOK_STUB_MEMORY_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self.__emu.mu.hook_add(UC_HOOK_CODE, self.__hook_stub, None, self.__stub_off, self.__stub_off+HOOK_STUB_MEMORY_SIZE)

    def __hook_func_head(self, mu: 'Uc', address, size, user_data):
        try:
            address = standlize_addr(address)
            if (address not in self.__hook_params):
                logging.debug("ignore hook on 0x%08X"%address)
                return

            logging.debug("trigger hook on 0x%08X"%address)
            hook_param = self.__hook_params[address]
            nargs = hook_param[0]
            args = native_read_args_in_hook_code(self.__emu, nargs)
            if (hook_param[1]):
                is_handled = hook_param[1](self.__emu, *args)
                if (is_handled):
                    # If the logic has already been processed, return directly.
                    if (self.__arch == emu_const.ARCH_ARM32):
                        cpsr = mu.reg_read(mu, UC_ARM_REG_CPSR)
                        lr = mu.reg_read(UC_ARM_REG_LR)
                        # same as BX LR
                        if (lr & 1):
                            # thumb set TF
                            cpsr = set_thumb(cpsr)
                        else:
                            # arm clear TF
                            cpsr = clear_thumb(cpsr)
                        mu.reg_write(UC_ARM_REG_CPSR, cpsr)
                        mu.reg_write(UC_ARM_REG_PC, lr)
                    else:
                        lr = mu.reg_read(UC_ARM64_REG_X30)
                        mu.reg_write(UC_ARM64_REG_PC, lr)
                    return

            if (hook_param[2]):
                # Since the last instruction is unknown, the only solution is to change the returned address and then hook it to achieve the callback after effect.
                # Change LR to return to the jump board.
                if (self.__arch == emu_const.ARCH_ARM32):
                    mu.mem_write(self.__stub_off, address.to_bytes(4, byteorder='little', signed=False))    # Write function address
                    self.__stub_off+=4

                    new_lr = self.__stub_off
                    # Jump back to the original return address
                    mu.mem_write(self.__stub_off, b"\x00\xE0\x9F\xE5")    #ldr lr, [pc, #0x0]
                    self.__stub_off+=4
                    mu.mem_write(self.__stub_off, b"\x1E\xFF\x2F\xE1")    #bx lr
                    self.__stub_off+=4
                    lr = mu.reg_read(UC_ARM_REG_LR)
                    mu.mem_write(self.__stub_off, lr.to_bytes(4, byteorder='little', signed=False)) # Backup return address
                    self.__stub_off+=4
                    mu.reg_write(UC_ARM_REG_LR, new_lr)
                else:
                    mu.mem_write(self.__stub_off, address.to_bytes(8, byteorder='little', signed=False))    # Write function address
                    self.__stub_off+=8

                    new_lr = self.__stub_off
                    mu.mem_write(self.__stub_off, b"\x5E\x00\x00\x58")    #ldr x30, #0x8
                    self.__stub_off+=4
                    mu.mem_write(self.__stub_off, b"\xC0\x03\x1F\xD6")    #br x30
                    self.__stub_off+=4

                    lr = mu.reg_read(UC_ARM64_REG_X30)
                    mu.mem_write(self.__stub_off, lr.to_bytes(8, byteorder='little', signed=False)) # Backup return address
                    self.__stub_off+=8
                    mu.reg_write(UC_ARM64_REG_X30, new_lr)

        except Exception as e:
            traceback.print_exc()
            os._exit(1)

    def hook_addr(self, addr: int, nargs: int, cb_before: Callable, cb_after: Optional[Callable] = None):
        addr = standlize_addr(addr)
        mu = self.__emu.mu
        mu.hook_add(UC_HOOK_CODE, self.__hook_func_head, None, addr, addr)
        self.__hook_params[addr] = (nargs, cb_before, cb_after)

    def fun_hook(self, *args, **kwargs):
        """
        fun_hook is deprecated, use hook_addr instead
        """
        DeprecationWarning("fun_hook is deprecated, use hook_addr instead")
        return self.hook_addr(*args, **kwargs)