    
import logging
import socket

from unicorn import Uc
from unicorn.arm_const import *

from .....const.android import *
from .....const.linux import *
from .....objects.virtual_file import VirtualFile

from unicorn import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator
    from ....pcb import Pcb


class NetworkSyscalls:
    def __init__(self, emulator: 'Emulator'):
        self.__emu: 'Emulator' = emulator
        self.__pcb: 'Pcb' = emulator.pcb

        self.__real_sockets = {}

    def _setsockopt(self, mu, fd, level, optname, optval, optlen):
            logging.warning("_setsockopt not implement skip")
            return 0

    def _socket(self, mu, family, type_in, protocol):
        # AF_UNIX = 1, AF_INET = 2, AF_NETLINK = 16
        type_in &= 0xFF

        # AF_NETLINK
        if family == 16:
            logging.debug("Creating Netlink socket (AF_NETLINK)")
            socket_id = self.__pcb.virtual_files.add_virtual_fd("[netlink]", "netlink_sock")
            return socket_id

        if family == 1:
            logging.debug("Creating UNIX socket (virtual)")
            socket_id = self.__pcb.virtual_files.add_virtual_fd("[unix]", "unix_sock")
            return socket_id

        try:
            s = socket.socket(family, type_in, protocol)
            s.setblocking(False)
        except Exception as e:
            logging.warning(f"socket error: {e}")
            return -1

        socket_id = s.fileno()
        self.__pcb.add_fd(f"[socket:{family}]", "network_sock", socket_id)

        return socket_id

    def _bind(self, mu, fd, addr, addr_len):

        # The struct is confusing..
        addr = mu.mem_read(addr + 3, addr_len - 3).decode(encoding="utf-8")

        logging.info('Binding socket to ://%s' % addr)
        raise NotImplementedError()
        return 0

    def _connect(self, mu, fd, addr, addr_len):
        sock = self.__pcb.virtual_files.get_fd_detail(fd)
        if not sock:
            return -1

        data = mu.mem_read(addr, addr_len)

        family = int.from_bytes(data[0:2], "little")

        logging.debug(f"connect fd={fd} family={family}")

        # AF_UNIX
        if family == 1:
            logging.debug("AF_UNIX connect (virtual)")
            return 0

        # AF_INET
        if family == 2:
            port = int.from_bytes(data[2:4], "big")
            ip = ".".join(str(b) for b in data[4:8])

            logging.info(f"connect {ip}:{port}")

            try:
                sock.connect((ip, port))
                return 0
            except BlockingIOError:
                return 0
            except Exception as e:
                logging.warning(f"connect error: {e}")
                return -1

        return 0