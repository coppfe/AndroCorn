# something will be here. Maybe. I don't know.

from .base_sym import BaseSymbolHooks

from typing import TYPE_CHECKING

from unicorn import *

from ...java.helpers.native_method import native_method

if TYPE_CHECKING:
    from unicorn import Uc
    from ...emulator import Emulator


class LibCPPSymbolHooks(BaseSymbolHooks):

    def __init__(self, emu: 'Emulator'):
        super().__init__(emu)
        
        self._emu = emu
        
        self.func_table = {
            # "__cxa_allocate_exception": self.cxa_allocate_exception,
            # "__cxa_throw": self.cxa_throw,
            # "__cxa_begin_catch": self.cxa_begin_catch,
            # "__cxa_guard_acquire": self.cxa_guard_acquire,
            # "__cxa_guard_release": self.cxa_guard_release,
        }

        self.global_func_table.update(self.func_table)
    
    @native_method
    def cxa_allocate_exception(self, uc, size):
        header_size = 0x90
        total_size = header_size + size
        ptr = self._emu.memory.map(0, total_size)
        return ptr + header_size

    @native_method
    def cxa_throw(self, uc, obj_ptr, tinfo_ptr, destr_ptr):
        raise RuntimeError("C++ Exception Thrown")
        # uc.emu_stop()
        return 0

    @native_method
    def cxa_begin_catch(self, uc, exc_ptr):
        return exc_ptr

    @native_method
    def cxa_guard_acquire(self, uc: 'Uc', guard_ptr):
        status = int.from_bytes(uc.mem_read(guard_ptr, 1), 'little')
        if status == 0:
            uc.mem_write(guard_ptr, b'\x01')
            return 1
        return 0

    @native_method
    def cxa_guard_release(self, uc, guard_ptr):
        uc.mem_write(guard_ptr, b'\x01')
        return 0