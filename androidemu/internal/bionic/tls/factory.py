import logging

from .init import BionicTLSInitialization

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from unicorn import Uc
    from androidemu.utils.memory.map import MemoryMap
    from androidemu.core.registers import RegistersMapping

logger = logging.getLogger(__name__)

def create_tls_backend(memory: 'MemoryMap', mu: 'Uc', registers: 'RegistersMapping'):
    logger.debug("[*] Creating TLS backend...")
    return BionicTLSInitialization(memory, mu, registers)