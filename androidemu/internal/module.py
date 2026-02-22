import logging
import struct
from typing import List, Dict, Optional, TYPE_CHECKING
import lief

if TYPE_CHECKING:
    from ..emulator import Emulator
    from unicorn import Uc
    from .elf_reader import ELFReader

logger = logging.getLogger(__name__)

class Module:
    def __init__(self, 
                 filename: str, 
                 load_base: int,
                 load_bias: int,
                 size: int, 
                 symbols: Dict[str, int], 
                 reader: 'ELFReader'):
        
        self.filename: str = filename
        self.filename_ptr: int = 0
        self.soinfo_ptr: int = 0
        self.base: int = load_base
        self.bias: int = load_bias
        self.tls_offset: int = 0
        self.size: int = size
        self.symbols: Dict[str, int] = symbols
        self.reader: 'ELFReader' = reader
        self.init_array: List[int] = []
        
        self.needed: List['Module'] = []
        self.initialized: bool = False

        self.symbol_lookup: Dict[int, str] = {}
        self._build_lookup()

    def _build_lookup(self):
        for name, offset in self.symbols.items():
            abs_addr = self.bias + offset
            self.symbol_lookup[abs_addr] = name

    def find_symbol(self, name: str) -> Optional[int]:
        offset = self.symbols.get(name)
        return (self.bias + offset) if offset is not None else None
    
    def find_function(self, name: str) -> Optional[int]:
        offset = self.reader.functions.get(name)
        return (self.bias + offset) if offset is not None else None

    def find_symbol_name(self, addr: int) -> Optional[str]:
        for target in [addr, addr | 1, addr & ~1]:
            if target in self.symbol_lookup:
                return self.symbol_lookup[target]
        return None

    def call_init(self, emu: 'Emulator'):
        init_funcs = self.init_array
        if not init_funcs:
            return

        logger.info(f"[*] Calling {len(init_funcs)} init functions for {self.filename}")
        logger.debug(f"init_array adjusted: {[hex(a) for a in init_funcs]}")

        for func in init_funcs:
            logger.debug(f"  [>] Calling init: {hex(func)} ({self.find_symbol_name(func) or 'unknown'})")
            emu.call_native(func)