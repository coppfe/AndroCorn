import logging
from typing import TYPE_CHECKING, Callable, Dict, List, Tuple

from unicorn import UC_HOOK_CODE

from ..const import emu_const
from ..types import ptr_t

if TYPE_CHECKING:
    from unicorn import Uc
    from ..core.emulator import Emulator

logger = logging.getLogger(__name__)


class Hooker:

    def __init__(self, emu: "Emulator", mu: "Uc", base_addr: int, size: int):
        self._emu = emu
        self._mu = mu
        self._memory = emu.memory
        self._ptr_sz = ptr_t.size
        self._is_64 = (emu.arch == emu_const.ARCH_ARM64)

        half = size // 2
        self._code_base = base_addr
        self._code_current = self._code_base
        self._code_limit = base_addr + half

        self._data_base = base_addr + half
        self._data_current = self._data_base

        # bx lr (ARM32) или ret (ARM64)
        self._stub_insn = b"\xC0\x03\x5F\xD6" if self._is_64 else b"\x1E\xFF\x2F\xE1"

        self._funcs_list: List[Callable] = []

        self._mu.hook_add(
            UC_HOOK_CODE,
            self._fast_hook_dispatch,
            None,
            self._code_base,
            self._code_limit
        )

    def write_function(self, func: Callable) -> int:
        """
        Allocates a clean 4-byte return trampoline and binds the Python callback.
        """
        hook_addr = self._code_current
        self._funcs_list.append(func)

        self._memory.write_bytes(hook_addr, self._stub_insn)
        self._code_current += 4

        return hook_addr

    def write_function_table(self, table: Dict[int, Callable]) -> Tuple[int, int]:
        """
        Writes function table pointers and returns (table_ptr_address, table_address).
        """
        max_idx = int(max(table, key=int)) + 1 if table else 0
        hook_map = {idx: self.write_function(cb) for idx, cb in table.items()}

        ptr_sz = self._ptr_sz
        table_bytes = bytearray(max_idx * ptr_sz)

        typecode = 'I' if ptr_sz == 4 else 'Q'
        mv = memoryview(table_bytes).cast(typecode)
        for idx, addr in hook_map.items():
            mv[idx] = addr

        table_addr = self._data_current
        self._memory.write_bytes(table_addr, table_bytes)
        self._data_current += len(table_bytes)

        ptr_addr = self._data_current
        self._memory.write_ptr(ptr_addr, table_addr)
        self._data_current += ptr_sz

        return ptr_addr, table_addr

    def _fast_hook_dispatch(self, mu: "Uc", address: int, size: int, user_data: None) -> None:
        idx = (address - self._code_base) >> 2

        try:
            self._funcs_list[idx](self._emu)
        except Exception:
            mu.emu_stop()
            logger.exception("Error inside native hook dispatch at %#x (index %d)", address, idx)
            raise