import os
import pickle
import logging
import lief

from functools import lru_cache

from typing import List, Dict, Any, Optional

from ..demangle import simple_demangle

logger = logging.getLogger(__name__)

class ELFReader:
    def __init__(self, filename: str, demangle: bool = False, use_cache: bool = True):
        self.filename = filename
        self.demangle = demangle
        
        self._cache_file = f"{filename}.cache"
        
        if use_cache and self._is_cache_valid():
            logger.info(f"Loading ELF from cache: {self._cache_file}")
            self._load_from_cache()
        else:
            logger.info(f"Parsing ELF with LIEF: {filename}")
            self._parse_with_lief()
            if use_cache:
                self._save_to_cache()

    def _is_cache_valid(self) -> bool:
        if not os.path.exists(self._cache_file):
            return False
        if os.path.getmtime(self.filename) > os.path.getmtime(self._cache_file):
            return False
        return True

    def _load_from_cache(self):
        with open(self._cache_file, 'rb') as f:
            state = pickle.load(f)
            self.__dict__.update(state)

    def _save_to_cache(self):
        with open(self._cache_file, 'wb') as f:
            pickle.dump(self.__dict__, f, protocol=pickle.HIGHEST_PROTOCOL)

    def _parse_with_lief(self):
        try:
            binary: lief.ELF.Binary = lief.parse(self.filename)
        except Exception as e:
            logger.error("Failed to parse ELF with LIEF: %s", e)
            raise

        if not binary:
            raise ValueError("LIEF returned None. Is this a valid ELF?")

        lief.disable_leak_warning()

        # -------- header meta --------
        self.is_32 = binary.header.identity_class == lief.ELF.Header.CLASS.ELF32
        self.is_lib = binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
        self.entry_point = binary.entrypoint
        
        self.phoff = binary.header.program_header_offset
        self.phdr_num = binary.header.numberof_segments

        # -------- precomputed lists & dicts --------
        self.needed_libs = list(binary.libraries)
        self._segments = self._extract_segments(binary)
        self._dynamic_tags = self._extract_dynamic_tags(binary)
        self._functions = self._extract_functions(binary)
        self._exports = self._extract_exports(binary)
        self.relocations = self._extract_relocations(binary)

        self._all_symbols = {**self._functions, **self._exports}
        
        self._tls_segment = next((s for s in self._segments if s["p_type"] == "TLS"), None)
        self._dyn_addr = next((s["p_vaddr"] for s in self._segments if s["p_type"] == "DYNAMIC"), 0)

        DT = lief.ELF.DynamicEntry.TAG
        self.android_rel_addr = binary.get(DT.ANDROID_REL).value if binary.has(DT.ANDROID_REL) else 0
        self.android_rela_addr = binary.get(DT.ANDROID_RELA).value if binary.has(DT.ANDROID_RELA) else 0
        self.has_relr = binary.has(DT.ANDROID_RELR) or binary.has(DT.RELR)

        del binary

    # =========================================================
    # EXTRACTORS
    # =========================================================

    def _extract_segments(self, binary: lief.ELF.Binary) -> List[Dict[str, Any]]:
        segments =[]
        for seg in sorted(binary.segments, key=lambda s: s.virtual_address):
            segments.append({
                "p_type": str(seg.type).split(".")[-1],
                "p_vaddr": seg.virtual_address,
                "p_paddr": seg.physical_address,
                "p_filesz": seg.physical_size,
                "p_memsz": seg.virtual_size,
                "p_flags": int(seg.flags),
                "p_align": seg.alignment,
                "content": bytes(seg.content), 
            })
        return segments

    def _extract_dynamic_tags(self, binary) -> Dict[str, int]:
        tags = {}
        DT = lief.ELF.DynamicEntry.TAG
        mapping = {
            DT.INIT: "DT_INIT", DT.INIT_ARRAY: "DT_INIT_ARRAY", DT.INIT_ARRAYSZ: "DT_INIT_ARRAYSZ",
            DT.FINI: "DT_FINI", DT.FINI_ARRAY: "DT_FINI_ARRAY", DT.FINI_ARRAYSZ: "DT_FINI_ARRAYSZ",
            DT.RELR: "DT_RELR", DT.SONAME: "DT_SONAME",
        }
        for k, v in mapping.items():
            if binary.has(k):
                tags[v] = binary.get(k).value
        return tags

    def _extract_functions(self, binary) -> Dict[str, int]:
        out = {}
        demangle_fn = simple_demangle if self.demangle else None
        for sym in binary.symbols:
            if sym.type == lief.ELF.Symbol.TYPE.FUNC:
                out[sym.name] = sym.value
                if demangle_fn:
                    nice = demangle_fn(sym.name)
                    if nice != sym.name:
                        out[nice] = sym.value
        return out

    def _extract_exports(self, binary) -> Dict[str, int]:
        exports = {}
        demangle_fn = simple_demangle if self.demangle else None
        for sym in binary.dynamic_symbols:
            if sym.value and sym.name:
                exports[sym.name] = sym.value
                if demangle_fn:
                    nice = demangle_fn(sym.name)
                    if nice != sym.name:
                        exports[nice] = sym.value
        return exports

    def _extract_relocations(self, binary) -> List[Dict[str, Any]]:
        rels =[]
        for r in binary.relocations:
            rels.append({
                "address": r.address,
                "type": r.type,
                "addend": r.addend,
                "symbol_name": r.symbol.name if r.has_symbol else None,
                "symbol_value": r.symbol.value if r.has_symbol else 0
            })
        return rels

    # =========================================================
    # PUBLIC API (Properties)
    # =========================================================

    @property
    def segments(self) -> List[Dict[str, Any]]:
        return self._segments

    @property
    def exported_symbols(self) -> Dict[str, int]:
        return self._exports

    @property
    def tls_segment(self):
        return self._tls_segment

    @property
    def dyn_addr(self) -> int:
        return self._dyn_addr

    @property
    def functions(self) -> Dict[str, int]:
        return self._functions

    # =========================================================
    # HELPERS
    # =========================================================

    def get_tag_val(self, tag_name: str) -> int:
        return self._dynamic_tags.get(tag_name, 0)

    def get_symbol_address(self, name: str) -> Optional[int]:
        return self._all_symbols.get(name)
    
    @lru_cache(maxsize=3)
    def get_segment(self, p_type: str) -> Optional[Dict[str, Any]]:
        for seg in self._segments:
            if seg["p_type"] == p_type:
                return seg
    
    def close(self):
        pass