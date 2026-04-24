import lief
import logging

from ..demangle import simple_demangle
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class ELFReader:
    def __init__(self, filename: str, demangle: bool):
        self.filename = filename
        self.demangle = demangle

        try:
            self.binary: lief.ELF.Binary = lief.parse(filename)
        except Exception as e:
            logger.error("Failed to parse ELF with LIEF: %s", e)
            raise

        if not self.binary:
            raise ValueError("LIEF returned None. Is this a valid ELF?")

        lief.disable_leak_warning()

        # -------- header meta --------
        self.is_32 = self.binary.header.identity_class == lief.ELF.Header.CLASS.ELF32
        self.is_lib = self.binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
        self.entry_point = self.binary.entrypoint

        # -------- hot local refs --------
        b = self.binary
        self._segments_raw = b.segments

        # -------- precomputed caches --------
        self._segments = self._parse_segments()
        self._dynamic_tags = self._parse_dynamic_tags()
        self._functions = self._parse_functions()
        self._exports = self._parse_exports()

        self._tls_segment = next(
            (s for s in self._segments if s["p_type"] == "TLS"),
            None
        )

        self._dyn_addr = self._compute_dyn_addr()

    # =========================================================
    # SEGMENTS
    # =========================================================

    def _parse_segments(self) -> List[Dict[str, Any]]:
        segments = []
        append = segments.append

        for seg in sorted(self._segments_raw, key=lambda s: s.virtual_address):
            seg_type = str(seg.type).split(".")[-1]

            append({
                "p_type": seg_type,
                "p_vaddr": seg.virtual_address,
                "p_paddr": seg.physical_address,
                "p_filesz": seg.physical_size,
                "p_memsz": seg.virtual_size,
                "p_flags": int(seg.flags),
                "p_align": seg.alignment,
                "content": seg.content,
            })

        return segments

    # =========================================================
    # DYNAMIC TAGS (optimized single lookup)
    # =========================================================

    def _parse_dynamic_tags(self) -> Dict[str, int]:
        tags = {}

        DT = lief.ELF.DynamicEntry.TAG
        b = self.binary

        mapping = {
            DT.INIT: "DT_INIT",
            DT.INIT_ARRAY: "DT_INIT_ARRAY",
            DT.INIT_ARRAYSZ: "DT_INIT_ARRAYSZ",
            DT.FINI: "DT_FINI",
            DT.FINI_ARRAY: "DT_FINI_ARRAY",
            DT.FINI_ARRAYSZ: "DT_FINI_ARRAYSZ",
            DT.RELR: "DT_RELR",
            DT.SONAME: "DT_SONAME",
        }

        has = b.has
        get = b.get

        for k, v in mapping.items():
            if has(k):
                tags[v] = get(k).value

        return tags

    # =========================================================
    # FUNCTIONS (cached once)
    # =========================================================

    def _parse_functions(self) -> Dict[str, int]:
        out = {}
        sym_type = lief.ELF.Symbol.TYPE.FUNC

        demangle = self.demangle
        demangle_fn = simple_demangle if demangle else None

        for sym in self.binary.symbols:
            if sym.type == sym_type:
                name = sym.name
                val = sym.value

                out[name] = val

                if demangle_fn:
                    nice = demangle_fn(name)
                    if nice != name:
                        out[nice] = val

        return out

    # =========================================================
    # EXPORTS (cached)
    # =========================================================

    def _parse_exports(self) -> Dict[str, int]:
        exports = {}

        demangle = self.demangle
        demangle_fn = simple_demangle if demangle else None

        for sym in self.binary.dynamic_symbols:
            if sym.value and sym.name:
                name = sym.name
                val = sym.value

                exports[name] = val

                if demangle_fn:
                    nice = demangle_fn(name)
                    if nice != name:
                        exports[nice] = val

        return exports

    # =========================================================
    # PROPERTIES (all O(1))
    # =========================================================

    @property
    def segments(self) -> List[Dict[str, Any]]:
        return self._segments

    @property
    def needed_libs(self) -> List[str]:
        return self.binary.libraries

    @property
    def relocations(self):
        return self.binary.relocations

    @property
    def exported_symbols(self) -> Dict[str, int]:
        return self._exports

    @property
    def android_rel_addr(self) -> int:
        t = lief.ELF.DynamicEntry.TAG.ANDROID_REL
        return self.binary.get(t).value if self.binary.has(t) else 0

    @property
    def android_rela_addr(self) -> int:
        t = lief.ELF.DynamicEntry.TAG.ANDROID_RELA
        return self.binary.get(t).value if self.binary.has(t) else 0

    @property
    def has_relr(self) -> bool:
        b = self.binary
        return (
            b.has(lief.ELF.DynamicEntry.TAG.ANDROID_RELR) or
            b.has(lief.ELF.DynamicEntry.TAG.RELR)
        )

    @property
    def phoff(self) -> int:
        return self.binary.header.program_header_offset

    @property
    def phdr_num(self) -> int:
        return self.binary.header.numberof_segments

    @property
    def tls_segment(self):
        return self._tls_segment

    @property
    def dyn_addr(self) -> int:
        return self._dyn_addr

    @property
    def header(self) -> lief.ELF.Header:
        return self.binary.header

    @property
    def functions(self) -> Dict[str, int]:
        return self._functions

    # =========================================================
    # HELPERS
    # =========================================================

    def _compute_dyn_addr(self) -> int:
        for s in self._segments_raw:
            if s.type == lief.ELF.Segment.TYPE.DYNAMIC:
                return s.virtual_address
        return 0

    def get_tag_val(self, tag_type) -> int:
        b = self.binary
        return b.get(tag_type).value if b.has(tag_type) else 0

    def get_symbol_address(self, name: str) -> Optional[int]:
        sym = self.binary.get_symbol(name)
        return sym.value if sym else None

    def close(self):
        del self.binary