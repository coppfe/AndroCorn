import lief
import logging

from typing import List, Dict, Any, Optional

from ..utils.demangle import simple_demangle

logger = logging.getLogger(__name__)

class ELFReader:
    def __init__(self, filename: str):
        self.filename = filename

        try:
            self.binary: lief.ELF.Binary = lief.parse(filename)
        except Exception as e:
            logger.error(f"Failed to parse ELF with LIEF: {e}")
            raise

        if not self.binary:
            raise ValueError("LIEF returned None. Is this a valid ELF?")

        self.is_32 = self.binary.header.identity_class == lief.ELF.Header.CLASS.ELF32
        self.is_lib = self.binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
        self.entry_point = self.binary.entrypoint

        self._segments: List[Dict[str, Any]] = self._parse_segments()
        self._dynamic_tags: Dict[str, int] = self._parse_dynamic_tags()
        self._functions: Dict[str, int] = self._parse_functions()

    def _parse_dynamic_tags(self) -> Dict[str, int]:
        tags = {}
        DT = lief.ELF.DynamicEntry.TAG
        
        mapping = {
            DT.INIT: "DT_INIT",
            DT.INIT_ARRAY: "DT_INIT_ARRAY",
            DT.INIT_ARRAYSZ: "DT_INIT_ARRAYSZ",
            DT.FINI: "DT_FINI",
            DT.FINI_ARRAY: "DT_FINI_ARRAY",
            DT.FINI_ARRAYSZ: "DT_FINI_ARRAYSZ",
            DT.RELR: "DT_RELR",
            DT.ANDROID_REL: "DT_ANDROID_REL",
            DT.ANDROID_REL_OFFSET: "DT_ANDROID_REL_OFFSET",
            DT.ANDROID_RELRSZ: "DT_ANDROID_RELRSZ",
            DT.ANDROID_RELA: "DT_ANDROID_RELA",
            DT.ANDROID_RELASZ: "DT_ANDROID_RELASZ",
            DT.STRTAB: "DT_STRTAB",
            DT.SYMTAB: "DT_SYMTAB",
            DT.PLTGOT: "DT_PLTGOT",
            DT.SONAME: "DT_SONAME"
        }

        for tag_enum, name in mapping.items():
            try:
                if self.binary.has(tag_enum):
                    entry = self.binary.get(tag_enum)
                    tags[name] = entry.value
            except Exception:
                pass

        return tags

    def _parse_segments(self) -> List[Dict[str, Any]]:
        segments = []
        sorted_segments = sorted(self.binary.segments, key=lambda s: s.virtual_address)

        for seg in sorted_segments:

            seg_type_str = str(seg.type).split('.')[-1]

            data = bytes(seg.content)
            segments.append({
                "p_type": seg_type_str,
                "p_vaddr": seg.virtual_address,
                "p_paddr": seg.physical_address,
                "p_filesz": seg.physical_size, 
                "p_memsz": seg.virtual_size,   
                "p_flags": int(seg.flags),     
                "p_align": seg.alignment,
                "content": data                
            })
            if seg_type_str == "LOAD":
                logger.debug(f"Parsed segment {seg_type_str}: {hex(seg.virtual_address)} size: {hex(seg.virtual_size)}")
                
        return segments
    
    def _parse_functions(self) -> List:
        temp = {}
        for sym in self.binary.symbols:
            if sym.type == lief.ELF.Symbol.TYPE.FUNC:
                sym.name = simple_demangle(sym.name)
                temp[sym.name] = sym.value
        return temp

    @property
    def segments(self) -> List[Dict[str, Any]]:
        return self._segments

    @property
    def needed_libs(self) -> List[str]:
        return [lib for lib in self.binary.libraries]

    @property
    def relocations(self):
        return self.binary.relocations

    @property
    def exported_symbols(self) -> Dict[str, int]:
        exports = {}
        for sym in self.binary.dynamic_symbols:
            if sym.value > 0 and sym.name:
                exports[sym.name] = sym.value
        return exports
    
    @property
    def android_rel_addr(self) -> int:
        if self.binary.has(lief.ELF.DynamicEntry.TAG.ANDROID_REL):
            return self.binary.get(lief.ELF.DynamicEntry.TAG.ANDROID_REL).value
        return 0

    @property
    def android_rela_addr(self) -> int:
        if self.binary.has(lief.ELF.DynamicEntry.TAG.ANDROID_RELA):
            return self.binary.get(lief.ELF.DynamicEntry.TAG.ANDROID_RELA).value
        return 0

    @property
    def has_relr(self) -> bool:
        return self.binary.has(lief.ELF.DynamicEntry.TAG.ANDROID_RELR) or \
               self.binary.has(lief.ELF.DynamicEntry.TAG.RELR)

    @property
    def phoff(self) -> int: return self.binary.header.program_header_offset
    
    @property
    def phdr_num(self) -> int: return self.binary.header.numberof_segments

    @property
    def tls_segment(self):
        return next((s for s in self._segments if s['p_type'] == 'TLS'), None)

    @property
    def dyn_addr(self) -> int:
        for s in self.binary.segments:
            if s.type == lief.ELF.Segment.TYPE.DYNAMIC:
                return s.virtual_address
        return 0
    @property
    def header(self) -> lief.ELF.Header: return self.binary.header

    @property
    def functions(self) -> Dict[str, int]: return self._functions
    
    def get_tag_val(self, tag_type) -> int:
        if self.binary.has(tag_type):
            return self.binary.get(tag_type).value
        return 0


    def get_symbol_address(self, name: str) -> Optional[int]:
        sym = self.binary.get_symbol(name)
        if sym:
            return sym.value
        return None

    def close(self):
        del self.binary