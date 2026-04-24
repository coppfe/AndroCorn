import logging
import socket

from typing import TYPE_CHECKING

from .....const.linux import *

if TYPE_CHECKING:
    from .....emulator import Emulator
    from .....pcb import Pcb


class NetworkSyscalls:
    def __init__(self, emulator: 'Emulator'):
        self.__emu = emulator
        self.__pcb: 'Pcb' = emulator.pcb

        self._real_sockets = {}

    # =========================================================
    # SOCKET
    # =========================================================

    def _socket(self, mu, family, type_in, protocol):
        type_in &= 0xff

        # -------------------------
        # AF_NETLINK (virtual)
        # -------------------------
        if family == 16:
            return self.__pcb.virtual_files.add_virtual_fd(
                "[netlink]",
                "netlink_socket"
            )

        # -------------------------
        # AF_UNIX (virtual)
        # -------------------------
        if family == 1:
            return self.__pcb.virtual_files.add_virtual_fd(
                "[unix]",
                "unix_socket"
            )

        # -------------------------
        # REAL SOCKET
        # -------------------------
        try:
            s = socket.socket(family, type_in, protocol)
            s.setblocking(False)
        except Exception as e:
            logging.warning("socket error: %s", e)
            return -EPERM

        fd = s.fileno()
        self._real_sockets[fd] = s

        self.__pcb.add_fd(
            "[socket:%d]" % fd,
            "network_socket",
            fd
        )

        return fd

    # =========================================================
    # SETSOCKOPT
    # =========================================================

    def _setsockopt(self, mu, fd, level, optname, optval, optlen):
        logging.warning("setsockopt not implemented (fd=%d)", fd)
        return 0

    # =========================================================
    # CONNECT
    # =========================================================

    def _connect(self, mu, fd, addr_ptr, addr_len):
        sock = self.__pcb.virtual_files.get_fd_detail(fd)
        if not sock:
            return -EPERM

        data = mu.mem_read(addr_ptr, addr_len)
        family = int.from_bytes(data[0:2], "little")

        # -------------------------
        # AF_UNIX
        # -------------------------
        if family == 1:
            logging.debug("AF_UNIX connect (virtual)")
            return 0

        # -------------------------
        # AF_INET
        # -------------------------
        if family == 2:
            port = int.from_bytes(data[2:4], "big")
            ip = ".".join(str(b) for b in data[4:8])

            logging.info("connect -> %s:%d", ip, port)

            real = self._real_sockets.get(fd)
            if not real:
                return -EPERM

            try:
                real.connect((ip, port))
            except BlockingIOError:
                pass
            except Exception as e:
                logging.warning("connect error: %s", e)
                return -EPERM

            return 0

        return 0

    # =========================================================
    # BIND
    # =========================================================

    def _bind(self, mu, fd, addr_ptr, addr_len):
        sock = self.__pcb.virtual_files.get_fd_detail(fd)
        if not sock:
            return -EPERM

        data = mu.mem_read(addr_ptr, addr_len)

        # skip sockaddr parsing noise safely
        addr = data[2:].split(b"\x00")[0].decode(errors="ignore")

        logging.info("bind -> %s", addr)

        sock.bound = True
        return 0