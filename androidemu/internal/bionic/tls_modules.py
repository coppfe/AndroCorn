import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...emulator import Emulator
    from ...utils.parsers.elf import ELFReader
    from .tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class TLSModuleLoader:
    def __init__(self, emu: 'Emulator', state: 'BionicTLS'):
        self.emu = emu
        self.state = state

    def register_module(self, reader: 'ELFReader') -> int:
        """
        Finds TLS segment, allocates memory, and registers it in DTV.
        """
        tls_seg = reader.tls_segment
        
        if not tls_seg or tls_seg.virtual_size == 0:
            return 0

        memsz = tls_seg.virtual_size
        tls_addr = self.emu.memory.static_alloc(memsz, align=0x10)

        content = bytes(tls_seg.content)
        if content:
            self.emu.mu.mem_write(tls_addr, content)

        module_id = self.state.dtv_builder.register_module(tls_addr)
        
        logger.debug("[TLS] Loaded module_id=%d: addr=%#x, size=%#x", 
                     module_id, tls_addr, memsz)
        
        return module_id