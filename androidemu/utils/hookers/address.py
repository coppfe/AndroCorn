import traceback
import logging
import os

from ...types import ptr_t

from unicorn import *

from ...const import emu_const
from ...data.mem_map import HOOK_STUB_MEMORY_SIZE
from ...native.helpers.method import read_args

from typing import TYPE_CHECKING, Callable, Optional
if TYPE_CHECKING:
    from ...core.emulator import Emulator

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
    def _hook_stub(self, mu: 'Uc', address, size, user_data):
        emu: 'Emulator' = user_data.get("emu")
        try:
            address = standlize_addr(address)

            fun_entry_addr = address - ptr_t.size
            fun_entry_bytes = mu.mem_read(fun_entry_addr, ptr_t.size)
            fun_entry = int.from_bytes(fun_entry_bytes, byteorder='little', signed=False)

            if (fun_entry in self._hook_params):
                hook_param = self._hook_params[fun_entry]
                nargs = hook_param[0]
                cb_after = hook_param[2]
                args = read_args(mu, nargs, emu.registers)
                cb_after(self._emu, *args)
                return
            
        except Exception as e:
            # Make sure we catch exceptions inside hooks and stop emulation.
            mu.emu_stop()
            traceback.print_exc()
            logging.exception("catch error on _hook")
            os._exit(-1)
            raise

    def __init__(self, emu: 'Emulator'):
        self._emu = emu
        self._arch = self._emu.arch
        self._hook_params = {}
        self._stub_off = self._emu.memory.map(0, HOOK_STUB_MEMORY_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self._emu.mu.hook_add(UC_HOOK_CODE, self._hook_stub, {"emu": emu}, self._stub_off, self._stub_off+HOOK_STUB_MEMORY_SIZE)

    def _hook_func_head(self, mu: 'Uc', address, size, user_data):
        try:
            address = standlize_addr(address)
            if (address not in self._hook_params):
                logging.debug("ignore hook on 0x%08X"%address)
                return

            logging.debug("trigger hook on 0x%08X"%address)
            hook_param = self._hook_params[address]
            nargs = hook_param[0]
            args = read_args(self._emu.mu, nargs, self._emu.registers)
            if (hook_param[1]):
                is_handled = hook_param[1](self._emu, *args)
                if (is_handled):
                    # If the logic has already been processed, return directly.
                    if (self._arch == emu_const.ARCH_ARM32):
                        cpsr = mu.reg_read(mu, self._emu.registers.cpsr)
                        lr = mu.reg_read(self._emu.registers.lr)
                        # same as BX LR
                        if (lr & 1):
                            # thumb set TF
                            cpsr = set_thumb(cpsr)
                        else:
                            # arm clear TF
                            cpsr = clear_thumb(cpsr)
                        mu.reg_write(self._emu.registers.cpsr, cpsr)
                        mu.reg_write(self._emu.registers.pc, lr)
                    else:
                        lr = mu.reg_read(self._emu.registers.lr)
                        mu.reg_write(self._emu.registers.pc, lr)
                    return

            if (hook_param[2]):
                # Since the last instruction is unknown, the only solution is to change the returned address and then hook it to achieve the callback after effect.
                # Change LR to return to the jump board.
                if (self._arch == emu_const.ARCH_ARM32):
                    mu.mem_write(self._stub_off, address.to_bytes(4, byteorder='little', signed=False))    # Write function address
                    self._stub_off+=4

                    new_lr = self._stub_off
                    # Jump back to the original return address
                    mu.mem_write(self._stub_off, b"\x00\xE0\x9F\xE5")    #ldr lr, [pc, #0x0]
                    self._stub_off+=4
                    mu.mem_write(self._stub_off, b"\x1E\xFF\x2F\xE1")    #bx lr
                    self._stub_off+=4
                    lr = mu.reg_read(self._emu.registers.lr)
                    mu.mem_write(self._stub_off, lr.to_bytes(4, byteorder='little', signed=False)) # Backup return address
                    self._stub_off+=4
                    mu.reg_write(self._emu.registers.lr, new_lr)
                else:
                    mu.mem_write(self._stub_off, address.to_bytes(8, byteorder='little', signed=False))    # Write function address
                    self._stub_off+=8

                    new_lr = self._stub_off
                    mu.mem_write(self._stub_off, b"\x5E\x00\x00\x58")    #ldr x30, #0x8
                    self._stub_off+=4
                    mu.mem_write(self._stub_off, b"\xC0\x03\x1F\xD6")    #br x30
                    self._stub_off+=4

                    lr = mu.reg_read(self._emu.registers.lr)
                    mu.mem_write(self._stub_off, lr.to_bytes(8, byteorder='little', signed=False)) # Backup return address
                    self._stub_off+=8
                    mu.reg_write(self._emu.registers.lr, new_lr)

        except Exception as e:
            traceback.print_exc()
            os._exit(1)

    def hook_addr(self, addr: int, nargs: int, cb_before: Callable, cb_after: Optional[Callable] = None):
        addr = standlize_addr(addr)
        mu = self._emu.mu
        mu.hook_add(UC_HOOK_CODE, self._hook_func_head, None, addr, addr)
        self._hook_params[addr] = (nargs, cb_before, cb_after)

    def fun_hook(self, *args, **kwargs):
        """
        fun_hook is deprecated, use hook_addr instead
        """
        # DeprecationWarning("fun_hook is deprecated, use hook_addr instead")
        return self.hook_addr(*args, **kwargs)