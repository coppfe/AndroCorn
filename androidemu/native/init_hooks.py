from typing import TYPE_CHECKING

import logging
from unicorn.arm_const import *

from .stub.base import StubAddress
from .hook.base import HookAddress

from .stub.libdl_sym import LibDLSymbolHooks

from .asset_mgr_hooks import AssetManagerHooks

if TYPE_CHECKING:
    from ..emulator import Emulator
    from ..utils.hookers.hook_addr import AddressHooker

logger = logging.getLogger(__name__)

SYM_HOOK_CLASSES = [
    LibDLSymbolHooks
]

class HooksInitializer:
    __slots__ = ('_emu', '__fun')

    def __init__(self, emu: 'Emulator'):
        self._emu: 'Emulator' = emu
        self.__fun: 'AddressHooker' = emu.address_hooker
        # self.resolver = TLSSymbolResolver(emu, self._emu.tls_state)

        for clz in SYM_HOOK_CLASSES:
            clz(emu) # system classes

        self._initialize()

    def _initialize(self):
        f_table = StubAddress.global_func_table

        for name, func in f_table.items():
            self._emu.linker.add_symbol_hook(name, self._emu._hooker.write_function(func))

        # self._emu.linker.add_symbol_hook('__tls_get_addr', self._emu._hooker.write_function(self.resolver.tls_get_addr))
        asset_hook = AssetManagerHooks(self._emu, self._emu.linker, self._emu._hooker, self._emu.vfs_root)
        asset_hook.register()

        logger.debug("[+] Symbol hooks initialized")

    def init_stubs(self):
        f_table = StubAddress.global_func_table

        for name, func in f_table.items():
            self._emu.linker.add_symbol_hook(name, self._emu._hooker.write_function(func))

        logger.debug("[+] Stubs initialized")

    def init_address_hooks(self):
        """
        Function hooks always initialize after relocations.
        """
        f_table = HookAddress.global_func_table

        for hook in f_table:
            symbol, num_args, before, after = hook[0], hook[1], hook[2], hook[3]

            if isinstance(symbol, str):
                sym_addr = self._emu.linker.find_function_by_name(symbol)

            elif isinstance(symbol, int):
                sym_addr = symbol
            else:
                raise TypeError(f"Unsupported symbol type: {type(symbol)}")
                        
            if sym_addr == 0:
                logging.debug("[!] Symbol %s not found as function name.", symbol)
                continue

            self.__fun.hook_addr(sym_addr, num_args, before, after)
            logger.debug("[+] Symbol %s hooked in %#x", symbol, sym_addr)