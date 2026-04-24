from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from .const import emu_const
import os
import traceback
import logging

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .emulator import Emulator

# Utility class to create a bridge between ARM and Python.
class Hooker:

    """
    :type emu androidemu.emulator.Emulator
    """
    def __init__(self, emu: 'Emulator', base_addr: int, size: int):
        self._emu: 'Emulator' = emu
        arch = emu.arch
        self._size = size
        self._current_id = 0xFF00
        self._hooks = dict()
        self._addr_to_hook = dict()
        _hook_start = base_addr + emu.ptr_size
        self._hook_current = _hook_start
        self._emu.mu.hook_add(UC_HOOK_CODE, self._hook, None, _hook_start, _hook_start + size)

    def _get_next_id(self):
        idx = self._current_id
        self._current_id += 1
        return idx

    #Returns the address of the function's starting point; if it's a thumb instruction, it's automatically incremented by 1.
    def write_function(self, func):
        # Get the hook id.
        hook_id = self._get_next_id()
        self._hooks[hook_id] = func
        #the the hook_id to header
        self._emu.mu.mem_write(self._hook_current, int(hook_id).to_bytes(4, byteorder='little', signed=False))
        self._hook_current+=4
        
        hook_addr = self._hook_current
        self._addr_to_hook[hook_addr] = func
        if (self._emu.arch == emu_const.ARCH_ARM32):
            # Create the ARM assembly code.
            # 注意，这里不要改sp，因为后面hook code会靠sp来定位参数
            # Write assembly code to the emulator.
            self._emu.mu.mem_write(self._hook_current, b"\x1E\xFF\x2F\xE1")  #bx lr
            self._hook_current += 4
        else:
            self._emu.mu.mem_write(self._hook_current, b"\xC0\x03\x5F\xD6")  #ret
            self._hook_current += 4 
        return hook_addr

    def write_function_table(self, table):
        if not isinstance(table, dict):
            raise ValueError("Expected a dictionary for the function table.")

        index_max = int(max(table, key=int)) + 1
        # First, we write every function and store its result address.
        hook_map = dict()

        for index, func in table.items():
            hook_map[index] = self.write_function(func)

        # Then we write the function table.
        table_bytes = b""
        table_address = self._hook_current
        ptr_size = self._emu.ptr_size
        for index in range(0, index_max):
            address = hook_map[index] if index in hook_map else 0
            table_bytes += int(address).to_bytes(ptr_size, byteorder='little')  # Write each function pointer into the pointer table.

        self._emu.mu.mem_write(table_address, table_bytes)
        self._hook_current += len(table_bytes)

        # Then we write the a pointer to the table.
        ptr_address = self._hook_current
        self._emu.mu.mem_write(ptr_address, table_address.to_bytes(ptr_size, byteorder='little'))
        self._hook_current += ptr_size
        return ptr_address, table_address

    def _hook(self, mu: 'Uc', address, size, user_data):
        hook_func = self._addr_to_hook[address & ~1]

        try:
            hook_func(self._emu)
        except Exception as e:
            mu.emu_stop()
            traceback.print_exc()
            logging.exception("catch error on _hook")
            os._exit(-1)
            raise