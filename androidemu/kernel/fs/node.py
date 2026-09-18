import zlib
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from .vdstat import VirtualDeviceStat
from ...const.linux import *
if TYPE_CHECKING:
    from androidemu.core.pcb import ProcessControlBlock
    
class VfsNode:
    def __init__(
        self,
        name: str,
        mode: int = 0o100644,
        uid: int = 0,
        gid: int = 0,
        dev: int = 0,
        rdev: int = 0,
        ino: Optional[int] = None,
    ):
        self.name = name
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.dev = dev
        self.rdev = rdev
        self.ino = ino if ino is not None else (zlib.adler32(name.encode()) & 0xFFFFFFFF)
        self.xattrs: Dict[str, bytes] = {}

    @property
    def is_dir(self) -> bool:
        """S_IFDIR (0o040000)"""
        return (self.mode & 0o170000) == 0o040000

    @property
    def is_symlink(self) -> bool:
        """S_IFLNK (0o120000)"""
        return (self.mode & 0o170000) == 0o120000

    @property
    def is_chr(self) -> bool:
        """S_IFCHR (0o020000)"""
        return (self.mode & 0o170000) == 0o020000

    @property
    def is_fifo(self) -> bool:
        """S_IFIFO (0o010000)"""
        return (self.mode & 0o170000) == 0o010000

    @property
    def is_sock(self) -> bool:
        """S_IFSOCK (0o140000)"""
        return (self.mode & 0o170000) == 0o140000

    def lookup(self, name: str) -> Optional['VfsNode']:
        return None

    def readlink(self) -> Optional[str]:
        return None

    def getdents(self) -> List[Tuple[str, int, int]]:
        return []

    def stat(self, time_manager) -> VirtualDeviceStat:
        return VirtualDeviceStat(
            st_mode=self.mode,
            st_size=self.get_size(),
            st_ino=self.ino,
            st_dev=self.dev,
            st_rdev=self.rdev,
            st_uid=self.uid,
            st_gid=self.gid,
            time_manager=time_manager
        )

    def read(self, offset: int, count: int) -> bytes:
        return b""

    def write(self, offset: int, data: bytes) -> int:
        return -1

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        return -25  # -ENOTTY (Inappropriate ioctl for device)

    def get_size(self) -> int:
        return 0


    def getxattr(self, name: str) -> Optional[bytes]:
        return self.xattrs.get(name)

    def setxattr(self, name: str, value: bytes) -> int:
        self.xattrs[name] = value
        return 0

    def listxattr(self) -> List[str]:
        return list(self.xattrs.keys())

    def check_permission(self, ctx: 'ProcessControlBlock', flags: int) -> int:
        if not ctx or ctx.uid == 0:
            return 0

        req = 0
        acc_mode = flags & 3
        if acc_mode == O_RDONLY:
            req = 4
        elif acc_mode == O_WRONLY:
            req = 2
        elif acc_mode == O_RDWR:
            req = 6

        if ctx.uid == self.uid:
            granted = (self.mode >> 6) & 7
        elif ctx.gid == self.gid:
            granted = (self.mode >> 3) & 7
        else:
            granted = self.mode & 7

        if (req & granted) != req:
            return -EACCES

        return 0


class VirtualDirNode(VfsNode):

    def __init__(self, name: str, mode: int = 0o040755, uid: int = 0, gid: int = 0, dev: int = 0):
        super().__init__(name=name, mode=mode, uid=uid, gid=gid, dev=dev)
        self.children: Dict[str, VfsNode] = {}

    def add_child(self, name: str, node: VfsNode) -> VfsNode:
        self.children[name] = node
        return node

    def lookup(self, name: str) -> Optional[VfsNode]:
        if name == ".":
            return self
        return self.children.get(name)

    def getdents(self) -> List[Tuple[str, int, int]]:
        # DT_DIR = 4, DT_LNK = 10, DT_REG = 8, DT_CHR = 2, DT_FIFO = 1, DT_SOCK = 12
        entries = [
            (".", 4, self.ino),
            ("..", 4, (self.ino ^ 0xFFFF) & 0xFFFFFFFF)
        ]
        for name, child in self.children.items():
            if child.is_dir:
                d_type = 4
            elif child.is_symlink:
                d_type = 10
            elif child.is_chr:
                d_type = 2
            elif child.is_fifo:
                d_type = 1
            elif child.is_sock:
                d_type = 12
            else:
                d_type = 8
            entries.append((name, d_type, child.ino))
        return entries


class RootVfsNode(VirtualDirNode):
    def __init__(self, host_dir_node: Optional[VfsNode] = None):
        super().__init__(name="/", mode=0o040755, uid=0, gid=0, dev=(259 << 8) | 0)
        self.host_dir_node = host_dir_node

    def lookup(self, name: str) -> Optional[VfsNode]:
        if name in self.children:
            return self.children[name]

        if self.host_dir_node is not None:
            return self.host_dir_node.lookup(name)

        return None

    def getdents(self) -> List[Tuple[str, int, int]]:
        entries = super().getdents()
        if self.host_dir_node is not None:
            host_entries = self.host_dir_node.getdents()
            existing_names = {e[0] for e in entries}
            for he in host_entries:
                if he[0] not in existing_names:
                    entries.append(he)
        return entries