import logging
import socket
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
                    5555
    }
    
    def __init__(self):
        self._real_sockets: Dict[int, socket.socket] = {}

    def _socket(self, emu: 'Emulator', family: int, type_in, protocol):
        type_in &= 0xFF

        # AF_NETLINK / AF_UNIX
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

    def _setsockopt(self, emu: 'Emulator', fd, level, optname, optval, optlen):
        return 0 # ?

    def _connect(self, emu: 'Emulator', fd, addr_ptr, addr_len):
        handle = emu.vfs.get_handle(fd)
        if not handle:
            return -EBADF

        data = emu.mu.mem_read(addr_ptr, addr_len)
        family = int.from_bytes(data[0:2], "little")

        if family == 1:
            return 0  # AF_UNIX success

        if family == 2:  # AF_INET
            port = int.from_bytes(data[2:4], "big")
            ip = ".".join(str(b) for b in data[4:8])
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

    def _bind(self, emu: 'Emulator', fd, addr_ptr, addr_len):
        handle = emu.vfs.get_handle(fd)
        if not handle:
            return -EBADF
        return 0