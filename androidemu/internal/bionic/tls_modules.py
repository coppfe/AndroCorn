import lief
import logging

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator
    from ..elf_reader import ELFReader
    from .tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class TLSModuleLoader:

    def __init__(self, emu: 'Emulator', state: 'BionicTLS'):
        self.emu = emu
        self.mu = emu.mu
        self.ptr_sz = emu.get_ptr_size()
        self.state: 'BionicTLS' = state

    def register_module(self, reader: 'ELFReader', load_bias: int) -> int:

        seg = self._find_tls_segment(reader)
        if not seg:
            return 0

        tls_block = self._allocate_tls_block(seg)
        
        self._populate_tls_block(seg, tls_block)

        module_id = self.state.dtv_builder.register_module(tls_block)
        
        logger.debug(f"[TLSLoader] Registered module_id={module_id} at {hex(tls_block)}")
        

        if not hasattr(self.state, 'modules'):
            self.state.modules = {}
            
        self.state.modules[module_id] = {
            "memsz": seg.virtual_size,
            "tdata": bytes(seg.content),
            "bias": load_bias
        }

        return module_id
    
    def _find_tls_segment(self, reader: 'ELFReader'):
        for seg in reader.binary.segments:
            if seg.type == lief.ELF.Segment.TYPE.TLS:
                if seg.virtual_size > 0:
                    return seg
        return None

    def _allocate_tls_block(self, seg: lief.ELF.Segment):
        memsz = seg.virtual_size
        addr = self.state.mem_reserve(memsz, align=0x10)
        return addr

    def _populate_tls_block(self, seg: lief.ELF.Segment, addr: int):
        content = bytes(seg.content)
        if content:
            self.mu.mem_write(addr, content)
        if seg.virtual_size > len(content):
            zero_sz = seg.virtual_size - len(content)
            self.mu.mem_write(addr + len(content), b'\x00' * zero_sz)
        