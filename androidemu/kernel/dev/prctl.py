import logging
from typing import Callable, Dict, Any

from ...const.android import *
from ...const.linux import *
from ...utils.memory import helpers
from ..backend.mocks import success

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.core.state._global import GlobalContextMachine
    from androidemu.data.states.process import ProcessState

logger = logging.getLogger(__name__)

PrctlCallback = Callable[[Any, int, int, int, int], int]

class PrctlHandler:
    def __init__(self, mu, ctx: 'GlobalContextMachine'):
        self._mu = mu

        self._state: 'ProcessState' = ctx

        self._dispatch_table: Dict[int, PrctlCallback] = {
            PR_SET_NAME:     self._handle_set_name,
            PR_GET_NAME:     self._handle_get_name,
            PR_SET_DUMPABLE: self._handle_set_dumpable,
            PR_GET_DUMPABLE: self._handle_get_dumpable,
            
            PR_SET_VMA:      success("PR_SET_VMA"),
            PR_SET_PTRACER:  self._handle_set_ptracer
        }


    def _handle_set_name(self, mu, arg2: int, *args) -> int:
        if arg2 != 0:
            self._state.process_name = helpers.read_utf8(mu, arg2).split('\0')[0]
        return 0

    def _handle_get_name(self, mu, arg2: int, *args) -> int:
        if arg2 != 0:
            name = (self._state.process_name[:15] + '\0').encode('utf-8')
            mu.mem_write(arg2, name)
        return 0

    def _handle_set_dumpable(self, mu, arg2: int, *args) -> int:
        if arg2 in (0, 1, 2):
            self._state.dumpable = arg2
            logger.debug("prctl: dumpable state changed to %d", arg2)
            return 0
        
        return -EINVAL

    def _handle_get_dumpable(self, *args) -> int:
        r = self._state.dumpable
        logger.debug("prctl: reporting dumpable state %d", r)
        return r
    
    def _handle_set_ptracer(self, mu, val, *args) -> int:
        tracer_pid = val 
            
        if tracer_pid == PR_SET_PTRACER_ANY:
            self._state.ptrace = True
        else:
            self._state.ptrace = tracer_pid
            
        return 0
    
    def handle(self, option: int, arg2: int, arg3: int, arg4: int, arg5: int) -> int:
        logger.debug(
            "prctl: option=%#x arg2=%016x arg3=%016x arg4=%016x arg5=%016x",
            option, arg2, arg3, arg4, arg5
        )

        handler = self._dispatch_table.get(option)
        if handler:
            return handler(self._mu, arg2, arg3, arg4, arg5)

        logger.warning("Unsupported prctl option %#x", option)
        return -EPERM