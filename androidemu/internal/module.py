import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from ..utils.parsers.elf import ELFReader
    from androidemu.core import Emulator

logger = logging.getLogger(__name__)


class Module:
    def __init__(
        self,
        filename: str,
        load_base: int,
        load_bias: int,
        size: int,
        dynamic: int,
        symbols: Dict[str, int],
        reader: 'ELFReader'
    ):
        self._reader: Optional['ELFReader'] = reader

        self.main_executable: bool = False
        self.filename: str = filename
        self.filename_ptr: int = 0
        self.soinfo_ptr: int = 0
        self.base: int = load_base
        self.bias: int = load_bias
        self.dynamic: int = dynamic
        self.tls_offset: int = 0
        self.size: int = size
        
        self.symbols: Dict[str, int] = symbols
        self.functions: Dict[str, int] = reader.functions if reader else {}
        self.segments: List[Dict[str, Any]] = reader.segments if reader else []
        self.dynamic_tags: Dict[str, int] = reader._dynamic_tags if reader else {}
        
        self.init_array: List[int] = []
        self.needed: List['Module'] = []
        self.initialized: bool = False

        self.symbol_lookup: Dict[int, str] = {}
        self._build_lookup()

    def _build_lookup(self) -> None:
        for name, offset in self.symbols.items():
            abs_addr = self.bias + offset
            self.symbol_lookup[abs_addr] = name

    def find_symbol(self, name: str) -> Optional[int]:
        offset = self.symbols.get(name)
        return (self.bias + offset) if offset is not None else None

    def find_function(self, name: str) -> Optional[int]:
        offset = self.functions.get(name)
        return (self.bias + offset) if offset is not None else None

    def find_symbol_name(self, addr: int) -> Optional[str]:
        for target in (addr, addr | 1, addr & ~1):
            if target in self.symbol_lookup:
                return self.symbol_lookup[target]
        return None

    def _unload_reader(self) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None

    def call_symbol(self, emu: 'Emulator', symbol_name: str, *argv: Any):
        emu.call_symbol(self, symbol_name, *argv)
    def call_function(self, emu: 'Emulator', function_name: str, *argv: Any):
        emu.call_function(self, function_name, *argv)
    def call_native(self, emu: 'Emulator', addr: int, *argv: Any):
        emu.call_native(addr, *argv)