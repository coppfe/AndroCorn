from typing import TYPE_CHECKING, Tuple

from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE

from ...data import layout as config
from ...utils.memory.helpers import align_down, align_up

if TYPE_CHECKING:
    from ...core.emulator import Emulator
    from ...internal.module import Module
    from ...utils.parsers.elf import ELFReader


class ELFMapper:

    def __init__(self, emu: 'Emulator'):
        self.emu = emu
        self.mem = emu.memory

    def map_segments(self, reader: 'ELFReader') -> Tuple[int, int, int]:
        load_segs = [s for s in reader.segments if s['p_type'] == "LOAD"]
        if not load_segs:
            raise RuntimeError("No LOAD segments found in ELF")

        min_v = min(s['p_vaddr'] for s in load_segs)
        max_v = max(s['p_vaddr'] + s['p_memsz'] for s in load_segs)

        aligned_min = align_down(min_v)
        aligned_max = align_up(max_v)
        total_span = aligned_max - aligned_min

        addr = self.mem.find_free_region(size=total_span, start_search=config.BASE_ADDR)
        base = self.mem.map(addr, total_span, prot=UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        bias = base - min_v

        for seg in load_segs:
            vaddr = seg['p_vaddr']
            content = bytes(seg.get('content', b''))
            dest = bias + vaddr

            if content:
                self.mem.write_bytes(dest, content)

        return base, bias, total_span

    def protect_module(self, module: 'Module') -> None:
        bias = module.bias

        for seg in module.segments:
            if seg['p_type'] != "LOAD":
                continue

            flags = seg.get('p_flags', 7)
            prot = 0
            if flags & 4: prot |= UC_PROT_READ
            if flags & 2: prot |= UC_PROT_WRITE
            if flags & 1: prot |= UC_PROT_EXEC

            start = align_down(bias + seg['p_vaddr'])
            size = align_up(bias + seg['p_vaddr'] + seg['p_memsz']) - start
            self.mem.protect(start, size, prot)

        for seg in module.segments:
            if seg['p_type'] == "GNU_RELRO":
                relro_start = align_down(bias + seg['p_vaddr'])
                relro_end = align_down(bias + seg['p_vaddr'] + seg['p_memsz'])
                if relro_end > relro_start:
                    self.mem.protect(relro_start, relro_end - relro_start, UC_PROT_READ)