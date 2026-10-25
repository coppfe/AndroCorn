import struct
import logging
import os

from typing import TYPE_CHECKING

from ...types import ptr_t

if TYPE_CHECKING:
    from ...core.emulator import Emulator
    from ..module import Module
    from ...utils.parsers.elf import ELFReader

logger = logging.getLogger(__name__)


class SoinfoWriter:
    """
    Soinfo builder specifically for Android 7.1.2 (Nougat, API 25).
    In Nougat, soinfo layout is more strict and includes a version field.
    """

    def __init__(self, emu: 'Emulator'):
        self.emu = emu
        self.mem = emu.memory
        self.ptr_sz = ptr_t.size
        self.is_64 = (self.ptr_sz == 8)
        self.fmt = "<Q" if self.is_64 else "<I"

    def write_soinfo(self, module: 'Module', reader: 'ELFReader', addr: int) -> int:
        struct_size = 0x300
        buffer = bytearray(struct_size)

        def safe_32(val: int) -> int:
            return val & 0xFFFFFFFF

        def write_ptr(offset: int, val: int) -> None:
            v = safe_32(val) if not self.is_64 else (val & 0xFFFFFFFFFFFFFFFF)
            struct.pack_into(self.fmt, buffer, offset, v)

        def write_u32(offset: int, val: int) -> None:
            struct.pack_into("<I", buffer, offset, safe_32(val))

        dynamic_addr = reader.dyn_addr

        if not self.is_64:
            name = os.path.basename(module.filename).encode('utf-8')[:127]
            buffer[0:len(name)] = name

            off = 0x80
            write_ptr(off + 0x00, module.base + reader.header.program_header_offset)  # phdr
            write_ptr(off + 0x04, reader.header.numberof_segments)                    # phnum
            write_ptr(off + 0x08, module.base + reader.header.entrypoint)             # entry
            write_ptr(off + 0x0C, module.base)                                        # base
            write_ptr(off + 0x10, module.size)                                        # size
            write_ptr(off + 0x14, dynamic_addr)                                       # dynamic
            write_ptr(off + 0x18, 0)                                                  # next (ptr)
            write_u32(off + 0x1C, 0x00000000)                                         # flags
            write_u32(off + 0x3C, 2)                                                  # version

            module.soinfo_ptr = addr
            self.mem.write_bytes(addr, buffer)
            return addr + off + 0x18
        else:
            # --- Android 7.1.2 ARM64 soinfo layout ---
            raw_name = module.filename.encode('utf-8') + b'\x00'
            name_ptr = self.mem.static_alloc(len(raw_name))
            self.mem.write_bytes(name_ptr, raw_name)
            module.filename_ptr = name_ptr

            write_ptr(0x00, name_ptr)                                                 # name ptr
            write_ptr(0x08, module.base + reader.header.program_header_offset)        # phdr
            write_ptr(0x10, reader.header.numberof_segments)                          # phnum
            write_ptr(0x18, module.base + reader.header.entrypoint)                   # entry
            write_ptr(0x20, module.base)                                              # base
            write_ptr(0x28, module.size)                                              # size
            write_ptr(0x30, dynamic_addr)                                             # dynamic
            write_ptr(0x38, 0)                                                        # next ptr
            write_u32(0x40, 0x00000000)                                               # flags
            write_u32(0x90, 2)                                                        # version

            module.soinfo_ptr = addr
            self.mem.write_bytes(addr, buffer)
            return addr + 0x38