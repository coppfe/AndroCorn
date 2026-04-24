import logging

from ......utils.memory import memory_helpers
from ......const.android import *
from ......const.linux import *

logging.getLogger(__name__)

class PrctlHandler:
    def __init__(self, mu, process_name="main_proc", ptr_sz=4):
        self._process_name = process_name
        self.__ptr_sz = ptr_sz
        
        self._dispatch_table = {
            PR_SET_VMA:      self._set_vma,
            PR_SET_DUMPABLE: self._set_dumpable,
            PR_GET_DUMPABLE: self._get_dumpable,
            PR_GET_NAME:     self._get_name,
            PR_SET_NAME:     self._set_name,
            PR_SET_PTRACER:  self._set_ptracer
        }

        self.__mu = mu

    def _set_ptracer(self, mu, arg2, *args):
        return 0

    def _set_vma(self, mu, arg2, arg3, arg4, arg5):
        return 0

    def _set_dumpable(self, mu, arg2, *args):
        return 0

    def _get_dumpable(self, mu, arg2, *args):
        if arg2:
            mu.mem_write(arg2, (1).to_bytes(4, "little"))
        return 0

    def _get_name(self, mu, arg2, *args):
        if arg2 != 0:
            name = (self._process_name[:15] + '\0').encode('utf-8')
            mu.mem_write(arg2, name)
        return 0

    def _set_name(self, mu, arg2, *args):
        if arg2 != 0:
            self._process_name = memory_helpers.read_utf8(mu, arg2).split('\0')[0]
        return 0

    def handle(self, option, arg2, arg3, arg4, arg5):
        logging.debug(
            "prctl: option=%#x arg2=%x arg3=%x arg4=%x arg5=%x",
            option, arg2, arg3, arg4, arg5
        )

        handler = self._dispatch_table.get(option)

        if handler:
            return handler(self.__mu, arg2, arg3, arg4, arg5)

        logging.warning("Unsupported prctl option %#x", option)
        return -EPERM