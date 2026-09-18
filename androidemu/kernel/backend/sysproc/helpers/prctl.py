import logging
from typing import Callable, Dict, Optional, TYPE_CHECKING

from .....const.android import (
    PR_SET_NAME,
    PR_GET_NAME,
    PR_SET_DUMPABLE,
    PR_GET_DUMPABLE,
    PR_SET_PTRACER,
    PR_SET_VMA,
    PR_SET_PTRACER_ANY,
)
from .....const.linux import EINVAL
from .....utils.memory import helpers

if TYPE_CHECKING:
    from androidemu import Emulator

logger = logging.getLogger(__name__)

PrctlHandlerFunc = Callable[['Emulator', int, int, int, int], int]
PrctlDefaultHandlerFunc = Callable[['Emulator', int, int, int, int, int], int]


class PrctlHandler:
    def __init__(self):
        self._handlers: Dict[int, PrctlHandlerFunc] = {}
        self._default_handler: Optional[PrctlDefaultHandlerFunc] = None
        self._register_defaults()

    def register(self, option: int, handler: PrctlHandlerFunc) -> None:
        self._handlers[option] = handler

    def set_default_handler(self, handler: PrctlDefaultHandlerFunc) -> None:
        self._default_handler = handler

    def handle(self, emu: 'Emulator', option: int, arg2: int, arg3: int, arg4: int, arg5: int) -> int:
        logger.debug(
            "prctl: option=0x%X arg2=0x%016X arg3=0x%016X arg4=0x%016X arg5=0x%016X",
            option, arg2, arg3, arg4, arg5
        )

        handler = self._handlers.get(option)
        if handler:
            return handler(emu, arg2, arg3, arg4, arg5)

        if self._default_handler:
            return self._default_handler(emu, option, arg2, arg3, arg4, arg5)

        logger.warning("Unsupported prctl option: 0x%X", option)
        return -EINVAL

    def _register_defaults(self) -> None:
        self.register(PR_SET_NAME, self._set_name)
        self.register(PR_GET_NAME, self._get_name)
        self.register(PR_SET_DUMPABLE, self._set_dumpable)
        self.register(PR_GET_DUMPABLE, self._get_dumpable)
        self.register(PR_SET_PTRACER, self._set_ptracer)
        self.register(PR_SET_VMA, self._mock_success)

    @staticmethod
    def _set_name(emu: 'Emulator', arg2: int, *args) -> int:
        if arg2 != 0:
            emu.pcb.process_name = helpers.read_utf8(emu.mu, arg2).split('\0')[0]
        return 0

    @staticmethod
    def _get_name(emu: 'Emulator', arg2: int, *args) -> int:
        if arg2 != 0:
            name = (emu.pcb.process_name[:15] + '\0').encode('utf-8')
            emu.mu.mem_write(arg2, name)
        return 0

    @staticmethod
    def _set_dumpable(emu: 'Emulator', arg2: int, *args) -> int:
        if arg2 in (0, 1, 2):
            emu.pcb.dumpable = arg2
            return 0
        return -EINVAL

    @staticmethod
    def _get_dumpable(emu: 'Emulator', *args) -> int:
        return emu.pcb.dumpable

    @staticmethod
    def _set_ptracer(emu: 'Emulator', val: int, *args) -> int:
        emu.pcb.ptrace = True if val == PR_SET_PTRACER_ANY else val
        return 0

    @staticmethod
    def _mock_success(emu: 'Emulator', *args) -> int:
        return 0