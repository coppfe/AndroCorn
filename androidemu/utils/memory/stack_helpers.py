from unicorn.arm_const import *
from unicorn.arm64_const import *
from ...const import emu_const
from . import helpers

from ...types import ptr_t

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...core.emulator import Emulator

class StackHelper():
    def __init__(self, emu: 'Emulator'):
        self.__emu: 'Emulator' = emu
        sp_reg = emu.registers.sp
        sp = emu.mu.reg_read(sp_reg)
        self.__sp = sp
        self.__sp_reg = sp_reg

    def reserve(self, nptr):
        self.__sp -= nptr * ptr_t.size
        return self.__sp

    def write_val(self, value):
        ptr_sz = ptr_t.size
        self.__sp -= ptr_sz
        helpers.write_uints(self.__emu.mu, self.__sp, value)
        return self.__sp

    def write_utf8(self, str_val):
        value_utf8 = str_val.encode(encoding="utf-8") + b"\x00"
        n = len(value_utf8)
        self.__sp -= n
        self.__emu.mu.mem_write(self.__sp, value_utf8)
        return self.__sp

    def commit(self):
        if(self.__emu.arch == emu_const.ARCH_ARM32):
            self.__sp = self.__sp & (~7)
        elif (self.__emu.arch == emu_const.ARCH_ARM64):
            self.__sp = self.__sp & (~15)
        self.__emu.mu.reg_write(self.__sp_reg, self.__sp)

    @property
    def stack_ptr(self):
        return self.__sp