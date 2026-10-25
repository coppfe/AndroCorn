import logging
import socket
import struct
from typing import TYPE_CHECKING, Dict

from ....const.linux import *
from ...fs.nodes.devices import SocketNode

if TYPE_CHECKING:
    from androidemu import Emulator


class NetworkSyscalls:
    SUSPICIOUS_PORTS = {
        23946,
        23947,
        27042,
        27043,
        1234,
        5555,
    }

    def __init__(self):
        self._real_sockets: Dict[int, socket.socket] = {}
        self._sock_buf = bytearray(128)

    def _socket(self, emu: 'Emulator', family: int, type_in: int, protocol: int) -> int:
        type_in &= 0xFF

        # AF_NETLINK (16) / AF_UNIX (1)
        if family == 16:
            return emu.vfs.create_fd_for_node(SocketNode("[netlink]"))
        if family == 1:
            return emu.vfs.create_fd_for_node(SocketNode("[unix]"))

        try:
            s = socket.socket(family, type_in, protocol)
            s.setblocking(False)
        except Exception as e:
            logging.warning("socket error: %s", e)
            return -EPERM

        fd = s.fileno()
        self._real_sockets[fd] = s
        return emu.vfs.create_fd_for_node(SocketNode(f"[socket:{fd}]", sock=s), specific_fd=fd)

    def _setsockopt(self, emu: 'Emulator', fd: int, level: int, optname: int, optval: int, optlen: int) -> int:
        return 0

    def _connect(self, emu: 'Emulator', fd: int, addr_ptr: int, addr_len: int) -> int:
        handle = emu.vfs.get_handle(fd)
        if not handle:
            return -EBADF

        if addr_len <= 0 or not addr_ptr:
            return -EINVAL

        read_len = min(addr_len, len(self._sock_buf))
        try:
            emu.memory.read_into(addr_ptr, self._sock_buf, read_len)
        except Exception:
            return -EFAULT

        # sa_family (uint16 little-endian)
        family = struct.unpack_from("<H", self._sock_buf, 0)[0]

        if family == 1:  # AF_UNIX
            return 0

        if family == 2:  # AF_INET
            # port (uint16 big-endian / network order)
            port = struct.unpack_from(">H", self._sock_buf, 2)[0]
            b = self._sock_buf
            ip = f"{b[4]}.{b[5]}.{b[6]}.{b[7]}"

            logging.info("connect -> %s:%d", ip, port)

            if (ip in ("127.0.0.1", "0.0.0.0", "localhost")) and (port in self.SUSPICIOUS_PORTS):
                logging.warning("[Anti-Debug Trap] Blocked probe to %s:%d -> Returning -ECONNREFUSED", ip, port)
                return -ECONNREFUSED

            real = self._real_sockets.get(fd)
            if not real:
                return -EPERM
            try:
                real.connect((ip, port))
            except BlockingIOError:
                pass
            except ConnectionRefusedError:
                return -ECONNREFUSED
            except Exception as e:
                logging.warning("connect error: %s", e)
                return -EPERM

            return 0

        return 0

    def _bind(self, emu: 'Emulator', fd: int, addr_ptr: int, addr_len: int) -> int:
        handle = emu.vfs.get_handle(fd)
        if not handle:
            return -EBADF
        return 0