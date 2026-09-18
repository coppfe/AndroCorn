import os
import sys
from ..node import VfsNode, VirtualDirNode
from typing import Optional, TYPE_CHECKING
from ....const.android import IOCTL_TCGETS, IOCTL_BINDER_VERSION, IOCTL_TIOCGPTN, IOCTL_TIOCSPTLCK, IOCTL_TIOCSTI
from ....const.linux import *
if TYPE_CHECKING:
    from androidemu.kernel.fs.manager import VFSManager
    from androidemu.core.pcb import ProcessControlBlock

class DevNullNode(VfsNode):
    def __init__(self):
        # /dev/null: S_IFCHR | 0666, devtmpfs (0:5), rdev (1:3)
        super().__init__(
            name="/dev/null",
            mode=0o020666,
            uid=0,
            gid=0,
            dev=0x0005,
            rdev=(1 << 8) | 3
        )

    def write(self, offset: int, data: bytes) -> int:
        return len(data)


class DevUrandomNode(VfsNode):
    def __init__(self):
        # /dev/urandom: S_IFCHR | 0666, devtmpfs (0:5), rdev (1:9)
        super().__init__(
            name="/dev/urandom",
            mode=0o020666,
            uid=0,
            gid=0,
            dev=0x0005,
            rdev=(1 << 8) | 9
        )

    def read(self, offset: int, count: int) -> bytes:
        return os.urandom(count)


class TtyNode(VfsNode):
    def __init__(
        self,
        name: str = "/dev/tty",
        mode: int = 0o020666,
        uid: int = 0,
        gid: int = 0,
        dev: int = 0x0005,
        rdev: int = (5 << 8) | 0
    ):
        super().__init__(
            name=name,
            mode=mode,
            uid=uid,
            gid=gid,
            dev=dev,
            rdev=rdev
        )
        self.stream_name = name

    def write(self, offset: int, data: bytes) -> int:
        try:
            if "stderr" in self.stream_name or self.name == "stderr":
                sys.stderr.buffer.write(data)
                sys.stderr.buffer.flush()
            else:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            return len(data)
        except Exception:
            return -EPERM

    def read(self, offset: int, count: int) -> bytes:
        return b""

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        if cmd == IOCTL_TCGETS:
            return 0
        return -ENOTTY


class BinderNode(VfsNode):
    def __init__(self):
        # /dev/binder: S_IFCHR | 0666, devtmpfs (0:5), misc rdev (10:54)
        super().__init__(
            name="/dev/binder",
            mode=0o020666,
            uid=0,
            gid=0,
            dev=0x0005,
            rdev=(10 << 8) | 54
        )

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        if cmd == IOCTL_BINDER_VERSION:
            mu.mem_write(arg, (8).to_bytes(4, 'little'))
            return 0
        return -EINVAL


class VirtualPipe:
    def __init__(self):
        self.buffer = bytearray()
        self.closed_write = False
        self.closed_read = False

    def write(self, data: bytes) -> int:
        if self.closed_read:
            return -EPIPE
        self.buffer.extend(data)
        return len(data)

    def read(self, count: int) -> bytes:
        if not self.buffer:
            return b""
        chunk = bytes(self.buffer[:count])
        del self.buffer[:count]
        return chunk


class PipeReadNode(VfsNode):
    def __init__(self, pipe: VirtualPipe, name: str = "[pipe_r]", uid: int = 0, gid: int = 0):
        # S_IFIFO | 0600, pipefs (0:8)
        super().__init__(
            name=name,
            mode=0o010600,
            uid=uid,
            gid=gid,
            dev=0x0008
        )
        self.pipe = pipe

    def read(self, offset: int, count: int) -> bytes:
        return self.pipe.read(count)

    def get_size(self) -> int:
        return len(self.pipe.buffer)

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        return 0


class PipeWriteNode(VfsNode):
    def __init__(self, pipe: VirtualPipe, name: str = "[pipe_w]", uid: int = 0, gid: int = 0):
        # S_IFIFO | 0600, pipefs (0:8)
        super().__init__(
            name=name,
            mode=0o010600,
            uid=uid,
            gid=gid,
            dev=0x0008
        )
        self.pipe = pipe

    def write(self, offset: int, data: bytes) -> int:
        return self.pipe.write(data)

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        return 0


class SocketNode(VfsNode):
    def __init__(self, name: str, sock=None, uid: int = 0, gid: int = 0):
        # S_IFSOCK | 0666, sockfs (0:7)
        super().__init__(
            name=name,
            mode=0o140666,
            uid=uid,
            gid=gid,
            dev=0x0007
        )
        self.sock = sock
        self.bound = False

    def read(self, offset: int, count: int) -> bytes:
        if self.sock:
            try:
                return self.sock.recv(count)
            except Exception:
                return b""
        return b""

    def write(self, offset: int, data: bytes) -> int:
        if self.sock:
            try:
                return self.sock.send(data)
            except Exception:
                return -EPERM
        return len(data)

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        return 0


class MemoryFileNode(VfsNode):
    def __init__(self, virt_path: str, data: bytes, mode: int = 0o100644, uid: int = 0, gid: int = 0, dev: int = 0):
        super().__init__(name=virt_path, mode=mode, uid=uid, gid=gid, dev=dev)
        self.data = bytearray(data)

    def read(self, offset: int, count: int) -> bytes:
        return bytes(self.data[offset:offset + count])

    def write(self, offset: int, data: bytes) -> int:
        end = offset + len(data)
        if end > len(self.data):
            self.data.extend(b'\x00' * (end - len(self.data)))
        self.data[offset:end] = data
        return len(data)

    def get_size(self) -> int:
        return len(self.data)

class PtmxNode(VfsNode):
    def __init__(self):
        # /dev/ptmx: S_IFCHR | 0666, devtmpfs (0:5), rdev (5:2)
        super().__init__(
            name="/dev/ptmx",
            mode=0o020666,
            uid=0,
            gid=0,
            dev=0x0005,
            rdev=(5 << 8) | 2
        )
        self.setxattr("security.selinux", b"u:object_r:ptmx_device:s0\x00")

    def check_permission(self, ctx: 'ProcessControlBlock', flags: int) -> int:
        return 0

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        if cmd == IOCTL_TIOCGPTN:
            mu.mem_write(arg, (0).to_bytes(4, 'little'))
            return 0
        if cmd == IOCTL_TIOCSPTLCK:
            return 0
        return 0

class PtsSlaveNode(TtyNode):
    def __init__(self, pty_num: int = 0, uid: int = 0):
        super().__init__(
            name=f"/dev/pts/{pty_num}",
            mode=0o020620,
            uid=uid,
            gid=5,  # GID 5 (tty)
            dev=0x000F,  # devpts (0:15)
            rdev=(136 << 8) | pty_num  # Unix98 PTY Slave 136:N
        )
        self.setxattr("security.selinux", b"u:object_r:devpts:s0\x00")

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        if cmd == IOCTL_TIOCSTI:
            return -EACCES
            
        if cmd == IOCTL_TCGETS:
            return 0
            
        return -ENOTTY

class DevPtsDirNode(VirtualDirNode):
    def __init__(self, vfs: Optional['VFSManager'] = None):
        super().__init__(name="/dev/pts", mode=0o040755, uid=0, gid=0, dev=0x000F)
        self.vfs = vfs
        self.setxattr("security.selinux", b"u:object_r:devpts:s0\x00")

    def lookup(self, name: str) -> Optional[VfsNode]:
        if name in self.children:
            return self.children[name]

        if name == "0":
            caller_uid = self.vfs.ctx.uid if (self.vfs and self.vfs.ctx) else 0
            slave_node = PtsSlaveNode(0, uid=caller_uid)
            self.children["0"] = slave_node
            return slave_node

        return None