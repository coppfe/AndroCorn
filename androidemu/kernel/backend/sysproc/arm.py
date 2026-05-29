from unicorn import Uc

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.utils.tls import BionicTLSUtils


class ARMSyscalls:
    def __init__(self, tls_utils: 'BionicTLSUtils'):
        self._tls_utils = tls_utils

    def _ARM_set_tls(self, mu: 'Uc', tls_ptr): self._tls_utils.set_tls(tls_ptr)
    # ARM_cacheflush mocked