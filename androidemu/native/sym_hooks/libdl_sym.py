from .base_sym import BaseSymbolHooks

from typing import TYPE_CHECKING

import logging
import random
import os

from unicorn import *

from ...java.helpers.native_method import native_method
from ...utils import memory_helpers


if TYPE_CHECKING:
    from unicorn import Uc
    from ...emulator import Emulator

logger = logging.getLogger(__name__)

class LibDLSymbolHooks(BaseSymbolHooks):

    def __init__(self, emu: 'Emulator'):
        super().__init__(emu)
        
        self._emu: 'Emulator' = emu
        
        self._func_table = {
            "dlopen": self.dlopen,
            "dlclose": self.dlclose,
            "dladdr": self.dladdr,
            "dlsym": self.dlsym,
            "dlerror": self.dlerror
        }

        self.global_func_table.update(self._func_table)
    
    @native_method
    def dlopen(self, uc: 'Uc', path_str: int, flags: int):
        if path_str == 0:
            if self._emu.linker.modules:
                main_mod = self._emu.linker.modules[0]
                logger.debug(f"[+] dlopen(NULL) -> returning main module: {main_mod.filename}")
                return main_mod.soinfo_ptr
            return 0

        path = memory_helpers.read_utf8(uc, path_str)
        logger.debug(f"[+] dlopen('{path}', flags={flags})")

        requested_basename = os.path.basename(path)
        for mod in self._emu.linker.modules:
            if os.path.basename(mod.filename) == requested_basename:
                logger.debug(f"[*] dlopen: '{path}' already loaded as {mod.filename}")
                return mod.soinfo_ptr

        fullpath = self._emu.linker.find_so_on_disk(path)
        
        if fullpath:

            mod = self._emu.load_library(fullpath, do_init=True)
            if mod:
                return mod.soinfo_ptr
        
        logger.warning(f"[!] dlopen: library '{path}' NOT FOUND")
        return 0


    @native_method
    def dlclose(self, uc, handle):
        """
        The function dlclose() decrements the reference count on the dynamic library handle handle.
        If the reference count drops to zero and no other loaded libraries use symbols in it, then the dynamic library is unloaded.
        """
        return 0

    @native_method
    def dladdr(self, uc: 'Uc', addr: int, info_ptr: int):
        ptr_sz = self._emu.get_ptr_size()
        
        for mod in self._emu.linker.linked_modules:
            if mod.base <= addr < mod.base + mod.size:
                fname_ptr = mod.filename_ptr 
                
                memory_helpers.write_ptrs_sz(uc, info_ptr, 
                                            [fname_ptr, mod.base, 0, 0], 
                                            ptr_sz)
                return 1
        return 0
    
    @native_method
    def dlsym(self, uc, handle, symbol_ptr):
        symbol_name = memory_helpers.read_utf8(uc, symbol_ptr)
        
        # ARM64: 0, ARM32: 0xffffffff
        is_64 = (self._emu.get_ptr_size() == 8)
        rtld_default = 0 if is_64 else 0xffffffff
        rtld_next = -1 if is_64 else -2 #future

        logger.debug(f"[+] dlsym(handle={hex(handle)}, symbol='{symbol_name}')")

        if handle == rtld_default:
            res = self._emu.linker.find_symbol_globally(symbol_name)
            return res

        target_module = None
        for mod in self._emu.linker.linked_modules:
            if mod.soinfo_ptr == handle:
                target_module = mod
                break
        
        if target_module:
            if symbol_name in target_module.symbols:
                return target_module.symbols[symbol_name]
            

            logger.warning(f"[!] dlsym: symbol '{symbol_name}' not found in module {target_module.filename}")
            return 0

        logger.error(f"[x] dlsym: Invalid handle {hex(handle)}")
        return 0
    
    @native_method
    def dlerror(self, uc):
        #Not implemented
        logger.error("[x] dlerror occurred")
        return 0