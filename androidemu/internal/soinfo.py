import struct
import logging
import os

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..emulator import Emulator
    from .module import Module
    from ..utils.parsers.elf import ELFReader

logger = logging.getLogger(__name__)

class SoinfoWriter:
    """
    Soinfo builder specifically for Android 7.1.2 (Nougat, API 25).
    In Nougat, soinfo layout is more strict and includes a version field.
    """

    def __init__(self, emu: 'Emulator'):
        self.emu = emu
        self.is_64 = (emu.ptr_size == 8)
        self.ptr_sz = emu.ptr_size
        self.fmt = "<Q" if self.is_64 else "<I"

    def write_soinfo(self, module: 'Module', reader: 'ELFReader', addr: int) -> int:
        struct_size = 0x300

        buffer = bytearray(struct_size)

        def safe_32(val):
            return val & 0xFFFFFFFF

        def write_ptr(offset: int, val: int):
            struct.pack_into(self.fmt, buffer, offset, safe_32(val))
        
        def write_u32(offset: int, val: int):
            struct.pack_into("<I", buffer, offset, safe_32(val))

        dynamic_addr = reader.dyn_addr

        if not self.is_64:
            # --- Android 7.1.2 ARM32 soinfo layout ---
            # 0x00: name[128] (Inline string)
            name = os.path.basename(module.filename).encode('utf-8')[:127]
            buffer[0:len(name)] = name
            
            off = 0x80
            write_ptr(off + 0x00, module.base + reader.header.program_header_offset) # phdr
            write_ptr(off + 0x04, reader.header.numberof_segments)                   # phnum
            write_ptr(off + 0x08, module.base + reader.header.entrypoint)            # entry
            write_ptr(off + 0x0C, module.base)                                       # base
            write_ptr(off + 0x10, module.size)                                       # size
            write_ptr(off + 0x14, dynamic_addr)                                      # dynamic
            write_ptr(off + 0x18, 0)                                                 # next (ptr)
            write_u32(off + 0x1C, 0x00000000)                                        # flags 
            write_u32(off + 0x3C, 2)                                                 # version
            
            module.soinfo_ptr = addr

            self.emu.mu.mem_write(addr, bytes(buffer))
            return addr + off + 0x18
        else:
            # --- Android 7.1.2 ARM64 soinfo layout ---
            name_ptr = self.emu.memory.static_alloc(len(module.filename) + 1)
            self.emu.mu.mem_write(name_ptr, module.filename.encode() + b'\x00')
            
            write_ptr(0x00, name_ptr)                                                # name ptr
            write_ptr(0x08, module.base + reader.header.program_header_offset)       # phdr
            write_ptr(0x10, reader.header.numberof_segments)                         # phnum
            write_ptr(0x18, module.base + reader.header.entrypoint)                  # entry
            write_ptr(0x20, module.base)                                             # base
            write_ptr(0x28, module.size)                                             # size
            write_ptr(0x30, dynamic_addr)                                            # dynamic
            write_ptr(0x38, 0)                                                       # next ptr
            write_u32(0x40, 0x00000000)                                              # flags (uint32_t)
            write_u32(0x90, 2)                                                       # version

            module.soinfo_ptr = addr
            
            self.emu.mu.mem_write(addr, bytes(buffer))
            return addr + 0x38