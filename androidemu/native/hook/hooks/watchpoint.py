import logging
from typing import TYPE_CHECKING, Callable, Dict, Optional
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ, UC_MEM_WRITE

if TYPE_CHECKING:
    from ....core.emulator import Emulator

logger = logging.getLogger("Watchpoint")


class WatchpointEntry:
    __slots__ = ("addr", "size", "tag", "on_read", "on_write")

    def __init__(
        self,
        addr: int,
        size: int,
        tag: str,
        on_read: Optional[Callable],
        on_write: Optional[Callable]
    ):
        self.addr = addr
        self.size = size
        self.tag = tag
        self.on_read = on_read
        self.on_write = on_write


class MemoryWatchpoint:
    """
    Tracks reads and writes to sensitive memory zones.
    """

    def __init__(self, emu: "Emulator"):
        self._emu = emu
        self._points: Dict[int, WatchpointEntry] = {}

    def add(
        self,
        addr: int,
        size: int,
        tag: str = "WATCH",
        on_read: Optional[Callable[["Emulator", int, int, int], None]] = None,
        on_write: Optional[Callable[["Emulator", int, int, int], None]] = None,
    ):
        """
        :param on_read: callback(emu, pc, addr, size)
        :param on_write: callback(emu, pc, addr, size, value)
        """
        entry = WatchpointEntry(addr, size, tag, on_read, on_write)
        self._points[addr] = entry

        self._emu.mu.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self._hook_mem_access,
            user_data=entry,
            begin=addr,
            end=addr + size - 1
        )
        logger.info("[+] Watchpoint set: [%s] at %#x - %#x (%d bytes)", tag, addr, addr + size, size)

    def _hook_mem_access(self, uc, access, address, size, value, user_data: WatchpointEntry):
        pc = self._emu.registers.v_pc

        sym = self._emu.linker.find_module_by_name
        caller_info = f"{pc:#x}"
        for mod in self._emu.linker.modules:
            if mod.base <= pc < mod.base + mod.size:
                sym_name = mod.find_symbol_name(pc) or f"+{pc - mod.base:#x}"
                caller_info = f"{mod.filename}:{sym_name}"
                break

        if access == UC_MEM_READ:
            logger.debug("[WATCH:READ] [%s] addr=%#x (sz=%d) by PC=%s", user_data.tag, address, size, caller_info)
            if user_data.on_read:
                user_data.on_read(self._emu, pc, address, size)
        elif access == UC_MEM_WRITE:
            logger.debug("[WATCH:WRITE] [%s] addr=%#x (sz=%d) = %#x by PC=%s", user_data.tag, address, size, value, caller_info)
            if user_data.on_write:
                user_data.on_write(self._emu, pc, address, size, value)