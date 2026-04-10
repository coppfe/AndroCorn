import logging

from ......const.android import *

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
        return -25 # ENOTTY

    def _handle_binder_version(self, fd, arg1, *args):
        binder_version = 8
        self.mu.mem_write(arg1, binder_version.to_bytes(4, 'little'))
        return 0

    def _handle_siocgifconf(self, fd, arg1, *args):
        logging.warning("SIOCGIFCONF: struct ifconf is not yet implemented")
        return -1 # EPERM

    def handle(self, fd, cmd, arg1, arg2, arg3, arg4):
        logging.debug(f"ioctl: fd={fd:#x} cmd={cmd:#x} arg1={arg1:#x}")

        handler = self._handlers.get(cmd)
        if handler:
            try:
                return handler(fd, arg1, arg2, arg3, arg4)
            except Exception as e:
                logging.error(f"Error in ioctl handler 0x{cmd:x}: {e}")
                return -22 # EINVAL
        
        logging.warning(f"Unknown ioctl cmd {cmd:#x} for fd {fd}")
        return -22 # EINVAL