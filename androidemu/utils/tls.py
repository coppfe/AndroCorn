from ..const.offsets.arm32 import *
from ..const.offsets.arm64 import *
from ..const.emu_const import *

from .memory import helpers

from ..types import ptr_t

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from unicorn.unicorn import Uc
    from androidemu.core.registers import RegistersMapping

class BionicTLSUtils:

    __slots__ = ("_mu", "_registers", "_errno_offset", "_ptr_size")

    def __init__(self, mu: 'Uc', registers: 'RegistersMapping'):
        
        self._mu = mu
        self._registers = registers
        self._ptr_size = ptr_t.size

        if mu._arch == ARCH_ARM32:
            self._errno_offset = ARM32_TLS_ERRNO
        else:
            self._errno_offset = ARM64_TLS_ERRNO
    
    def set_errno(self, errno):
        tls = self._mu.reg_read(self._registers.tls)
        slot = tls + self._errno_offset

        helpers.write_uints(self._mu, slot, errno)
        return 0
    
    def set_tls(self, tls_ptr):
        self._mu.reg_write(self._registers.tls, tls_ptr)
        return 0