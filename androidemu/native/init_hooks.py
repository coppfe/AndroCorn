from typing import TYPE_CHECKING

import logging
from unicorn.arm_const import *

from .linker.libdl_sym import LibDLSymbolHooks
from .asset_mgr_hooks import AssetManagerHooks

if TYPE_CHECKING:
    from ..core.emulator import Emulator

logger = logging.getLogger(__name__)

SYM_HOOK_CLASSES = [
    LibDLSymbolHooks,
    AssetManagerHooks
]

class HooksInitializer:
    __slots__ = ('_emu', '__fun')

    def __init__(self, emu: 'Emulator'):
        self._emu: 'Emulator' = emu
        # self.resolver = TLSSymbolResolver(emu, self._emu.tls_state)
        # self._emu.linker.add_symbol_hook('__tls_get_addr', self._emu._hooker.write_function(self.resolver.tls_get_addr))

        for clz in SYM_HOOK_CLASSES:
            clz(self._emu) # system classes

        logger.debug("[+] Symbol hooks initialized")