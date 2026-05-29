import logging

from ...const import emu_const
from .arm32.tls_bootstrap import BionicTLS_ARM32
from .arm64.tls_bootstrap import BionicTLS_ARM64

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from unicorn import Uc
    from androidemu.utils.memory.map import MemoryMap

logger = logging.getLogger(__name__)

def create_tls_backend(memory: 'MemoryMap', mu: 'Uc', arch: int):
    arch_str = 'ARM32' if arch == emu_const.ARCH_ARM32 else 'ARM64'
    logger.debug("[*] Creating TLS backend for arch: %s", arch_str)

    if arch == emu_const.ARCH_ARM32:
        return BionicTLS_ARM32(memory, mu)
    elif arch == emu_const.ARCH_ARM64:
        return BionicTLS_ARM64(memory, mu)
    else:
        raise NotImplementedError("TLS not implemented for arch: %d" % arch)