import struct
import logging
import lief
import os

from typing import List, TYPE_CHECKING

from . import elf_reader
from ..utils import memory_helpers
from ..const.emu_const import *

if TYPE_CHECKING:
    from ..emulator import Emulator
    from unicorn import Uc
    from .module import Module
    from .elf_reader import ELFReader

logging.getLogger(__name__)

# shit?

class SoinfoWriter:
    def __init__(self, emu: 'Emulator'):
        self.emu: 'Emulator' = emu
        self.is_64bit = (emu.get_arch() == ARCH_ARM64)
        self.ptr_sz = self.emu.get_ptr_size()
        self.ptr_fmt = "<Q" if self.is_64bit else "<I"

    def write_soinfo(self, module: 'Module', reader: 'ELFReader') -> int:

        mu = self.emu.mu
        base = module.base
        bias = module.bias
        
        start_offset = 128 if not self.is_64bit else 0
        
        struct_size = 0x300
        data = bytearray(struct_size)

        def p(offset, val):
            try:
                struct.pack_into(self.ptr_fmt, data, start_offset + offset, val)
            except struct.error:
                logging.error(f"[Soinfo] Pack error at offset {offset}, val {val}")

        def tag(name):
            val = reader._dynamic_tags.get(name)
            return val if val is not None else 0

        if not self.is_64bit:
            name_bytes = os.path.basename(module.filename).encode('utf-8')[:127]
            struct.pack_into(f"128s", data, 0, name_bytes)

        # ptr_t phdr;
        phdr_addr = base + reader.header.program_header_offset
        p(0x00, phdr_addr)
        
        # size_t phnum;
        p(self.ptr_sz, reader.header.numberof_segments)
        
        # ptr_t base;
        off_base = 0x0C if not self.is_64bit else 0x18
        p(off_base, base)
        
        # size_t size;
        p(off_base + self.ptr_sz, module.size)
        
        # ptr_t dynamic;
        dyn_val = tag("DT_NULL_ADDR")

        if dyn_val == 0: 
            for seg in reader.segments:
                if seg['p_type'] == 'DYNAMIC':
                    dyn_val = bias + seg['p_vaddr']
                    break
        p(off_base + 2 * self.ptr_sz + 4, dyn_val)

        # ptr_t next; 
        next_offset = 0x24 if not self.is_64bit else 0x38

        p(next_offset, 0) # Placeholder

        # TODO: --- 2.0 Symbol & Relocation tables ---

        mu.mem_write(module.soinfo_ptr, bytes(data))
        
        return module.soinfo_ptr + start_offset + next_offset