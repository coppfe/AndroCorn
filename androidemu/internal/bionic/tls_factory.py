import logging

from ...const import emu_const
from .arm32.tls_bootstrap import BionicTLS_ARM32
from .arm64.tls_bootstrap import BionicTLS_ARM64

logger = logging.getLogger(__name__)

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator

def create_tls_backend(emu: 'Emulator'):
    arch = emu.get_arch()

    logger.debug(f"[*] Creating TLS backend for arch: {'ARM32' if arch == emu_const.ARCH_ARM32 else 'ARM64'}")

    if arch == emu_const.ARCH_ARM32:
        return BionicTLS_ARM32(emu)
    elif arch == emu_const.ARCH_ARM64:
        return BionicTLS_ARM64(emu)
    else:
        raise NotImplementedError(f"TLS not implemented for arch: {arch}")