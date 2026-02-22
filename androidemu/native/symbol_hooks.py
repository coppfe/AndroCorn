from typing import TYPE_CHECKING

import logging
from unicorn.arm_const import *

from .sym_hooks.base_sym import BaseSymbolHooks
from .fun_hooks.base_fun import BaseFuncHooks

from .sym_hooks.libdl_sym import LibDLSymbolHooks
from .sym_hooks.libc_sym import LibCSymbolHooks
from .sym_hooks.libcpp_sym import LibCPPSymbolHooks

from .fun_hooks.libc_fun import LibCFunHooks

from ..internal.bionic.tls_resolver import TLSSymbolResolver

from .asset_mgr_hooks import AssetManagerHooks
from ..utils import memory_helpers

if TYPE_CHECKING:
    from ..emulator import Emulator
    from ..native_hook_utils import FuncHooker

logger = logging.getLogger(__name__)

SYM_HOOK_CLASSES = [ # for exported symbols call
    LibDLSymbolHooks,
    LibCSymbolHooks,
    LibCPPSymbolHooks
]

FUNC_HOOK_CLASSES = [ # for non-exported calls
    LibCFunHooks
]

from ..java.helpers.native_method import native_method

class SymbolHooks:

    def __init__(self, emu: 'Emulator'):
        self._emu: 'Emulator' = emu
        self.fun: 'FuncHooker' = emu.func_hooker
        self.resolver = TLSSymbolResolver(emu, self._emu.tls_state)

        for clz in SYM_HOOK_CLASSES:
            clz(emu)

        for clz in FUNC_HOOK_CLASSES:
            clz(emu)

        self._initialize()

    def _initialize(self):
        f_table = BaseSymbolHooks.global_func_table

        for name, func in f_table.items():
            self._emu.linker.add_symbol_hook(name, self._emu._hooker.write_function(func))

        # self._emu.linker.add_symbol_hook('__tls_get_addr', self._emu._hooker.write_function(self.resolver.tls_get_addr))
        asset_hook = AssetManagerHooks(self._emu, self._emu.linker, self._emu._hooker, self._emu.get_vfs_root())
        asset_hook.register()

        logger.debug("[+] Symbol hooks initialized")

    def init_fun_hooks(self):
        """
        Local function hooks always initialize after relocations.
        """
        f_table = BaseFuncHooks.global_func_table

        for hook in f_table:
            symbol, num_args, before, after = hook[0], hook[1], hook[2], hook[3]
            sym_addr = self._emu.linker.find_function_by_name(symbol)

            if sym_addr == 0:
                logger.warning(f"[!] Symbol {symbol} not found")
                continue

            self.fun.fun_hook(sym_addr, num_args, before, after)
            logger.debug(f"[+] Symbol {symbol} hooked in {hex(sym_addr)}")