from .base import StubAddress

from typing import TYPE_CHECKING

import logging
import os

from unicorn import *

from ..helpers.method import native_method
from ...utils.memory import helpers

from ...types import ptr_t

if TYPE_CHECKING:
    from ...core.emulator import Emulator

logger = logging.getLogger(__name__)

class LibDLSymbolHooks(StubAddress):

    def __init__(self):
        super().__init__()
        
        
        self._func_table = {
            "dlopen": self.dlopen,
            "dlclose": self.dlclose,
            "dladdr": self.dladdr,
            "dlsym": self.dlsym,
            "dlerror": self.dlerror
        }

        self.global_func_table.update(self._func_table)
    
    @native_method
    def dlopen(self, emu: 'Emulator', path_str: int, flags: int):
        if path_str == 0:
            if emu.linker.modules:
                main_mod = emu.linker.modules[0]
                logger.debug("[+] dlopen(NULL) -> returning main module: %s", main_mod.filename)
                return main_mod.soinfo_ptr
            return 0

        path = helpers.read_utf8(emu.mu, path_str)
        logger.debug("[+] dlopen('%s', flags=0x%x)", path, flags)

        requested_basename = os.path.basename(path)
        for mod in emu.linker.modules:
            if os.path.basename(mod.filename) == requested_basename:
                logger.debug("[*] dlopen: '%s' already loaded as %s", path, mod.filename)
                return mod.soinfo_ptr

        fullpath = emu.linker.find_so_on_disk(path)
        
        if fullpath:

            mod = emu.load_library(fullpath, do_init=True)
            if mod:
                return mod.soinfo_ptr
        
        logger.warning("[!] dlopen: library '%s' NOT FOUND", path)
        return 0


    @native_method
    def dlclose(self, emu, handle):
        """
        The function dlclose() decrements the reference count on the dynamic library handle handle.
        If the reference count drops to zero and no other loaded libraries use symbols in it, then the dynamic library is unloaded.
        """
        return 0

    @native_method
    def dladdr(self, emu: 'Emulator', addr: int, info_ptr: int):
        
        for mod in emu.linker.modules:
            if mod.base <= addr < mod.base + mod.size:
                fname_ptr = mod.filename_ptr 
                
                helpers.write_uints(emu.mu, info_ptr, 
                                            [fname_ptr, mod.base, 0, 0], 
                                   )
                return 1
        return 0
    
    @native_method
    def dlsym(self, emu: 'Emulator', handle, symbol_ptr):
        symbol_name = helpers.read_utf8(emu.mu, symbol_ptr)
        
        is_64 = (ptr_t.size == 8)
        rtld_default = 0 if is_64 else 0xffffffff

        logger.debug("[+] dlsym(handle=%#x, symbol='%s')", handle, symbol_name)

        if symbol_name in emu.linker.symbol_hooks:
            return emu.linker.symbol_hooks[symbol_name]

        if handle == rtld_default:
            res = emu.linker.find_symbol_globally(symbol_name)
            if res is not None:
                return res
            return 0

        target_module = None
        for mod in emu.linker.modules:
            if mod.soinfo_ptr == handle:
                target_module = mod
                break
        
        if target_module:
            addr = target_module.find_symbol(symbol_name)
            if addr is not None:
                return addr
            
            for m in emu.linker.modules:
                addr = m.find_symbol(symbol_name)
                if addr is not None:
                    logger.debug("[+] dlsym: '%s' fallback found in %s", symbol_name, m.filename)
                    return addr

            logger.warning("[!] dlsym: symbol '%s' not found in module %s", symbol_name, target_module.filename)
            return 0

        logger.error("[x] dlsym: Invalid handle %#x", handle)
        return 0
    
    @native_method
    def dlerror(self, emu):
        #Not implemented
        logger.error("[x] dlerror occurred")
        return 0