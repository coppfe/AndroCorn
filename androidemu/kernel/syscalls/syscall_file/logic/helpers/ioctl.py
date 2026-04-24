import logging

from ......const.android import *
from ......const.linux import *

class IoctlHandler:
    def __init__(self, mu):
        logging.getLogger(__name__)
        
        self.mu = mu

        self._handlers = {
            IOCTL_TCGETS:               self._handle_tcgets,
            IOCTL_BINDER_VERSION:       self._handle_binder_version,
            IOCTL_SIOCGIFCONF:          self._handle_siocgifconf,
        }

    def _handle_tcgets(self, fd, arg1, *args):
        if fd in (1, 2): 
            return 0  # TTY
        return -ENOTTY # ENOTTY

    def _handle_binder_version(self, fd, arg1, *args):
        binder_version = 8
        self.mu.mem_write(arg1, binder_version.to_bytes(4, 'little'))
        return 0

    def _handle_siocgifconf(self, fd, arg1, *args):
        logging.warning("SIOCGIFCONF: struct ifconf is not yet implemented")
        return -EPERM

    def handle(self, fd, cmd, arg1, arg2, arg3, arg4):
        logging.debug("ioctl: fd=%#x cmd=%#x arg1=%#x arg2=%#x arg3=%#x arg4=%#x", fd, cmd, arg1, arg2, arg3, arg4)

        handler = self._handlers.get(cmd)
        if handler:
            try:
                return handler(fd, arg1, arg2, arg3, arg4)
            except Exception as e:
                logging.error("Error in ioctl handler %#x: %s", cmd, e)
                return -EINVAL
        
        logging.warning("Unknown ioctl cmd 0x%#x for fd %d", cmd, fd)
        return -EINVAL