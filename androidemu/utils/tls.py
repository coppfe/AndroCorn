import logging

from ..const.offsets.arm32 import *
from ..const.offsets.arm64 import *
from ..const.emu_const import *

from .memory import memory_helpers

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..emulator import Emulator

class BionicTLSUtils:

    __slots__ = ("__emu", "__errno_offset")

    def __init__(self, emulator: "Emulator"):
        self.__emu = emulator

        if self.__emu.arch == ARCH_ARM32:
            self.__errno_offset = ARM32_TLS_ERRNO
        else:
            self.__errno_offset = ARM64_TLS_ERRNO
    
    def set_errno(self, errno):
        __tls = self.__emu.mu.reg_read(self.__emu.scheduler._reg_tls)
        __slot = __tls + self.__errno_offset
        memory_helpers.write_uints(self.__emu.mu, __slot, errno)
        return 0
    
    def set_tls(self, tls_ptr):
        self.__emu.mu.reg_write(self.__emu.scheduler._reg_tls, tls_ptr)
        return 0