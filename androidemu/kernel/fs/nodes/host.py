import os
import zlib
import posixpath
from typing import List, Tuple, Optional, TYPE_CHECKING
from ..node import VfsNode, VirtualDirNode
from ..vdstat import VirtualDeviceStat
from ....const.linux import DT_DIR, DT_REG, DT_LNK

if TYPE_CHECKING:
    from ..mounts import MountTable


class HostFileNode(VfsNode):

    def __init__(
        self,
        virt_path: str,
        host_path: str,
        mode: int = 0o100644,
        uid: int = 0,
        gid: int = 0,
        dev: int = 0,
    ):
        super().__init__(name=virt_path, mode=mode, uid=uid, gid=gid, dev=dev)
        self.host_path = host_path

    def stat(self, time_manager) -> VirtualDeviceStat:
        st = os.stat(self.host_path)
        return VirtualDeviceStat(
            st_mode=self.mode,
            st_size=st.st_size,
            st_ino=self.ino,
            st_dev=self.dev,
            st_rdev=self.rdev,
            st_uid=self.uid,
            st_gid=self.gid,
            st_nlink=st.st_nlink,
            time_manager=time_manager
        )

    def read(self, offset: int, count: int) -> bytes:
        try:
            with open(self.host_path, "rb") as f:
                f.seek(offset)
                return f.read(count)
        except OSError:
            return b""

    def write(self, offset: int, data: bytes) -> int:
        try:
            mode = "r+b" if os.path.exists(self.host_path) else "wb"
            with open(self.host_path, mode) as f:
                f.seek(offset)
                return f.write(data)
        except OSError:
            return -1

    def get_size(self) -> int:
        try:
            return os.path.getsize(self.host_path)
        except OSError:
            return 0


class HostDirNode(VirtualDirNode):

    def __init__(
        self,
        virt_path: str,
        host_path: str,
        mount_table: 'MountTable',
        mode: int = 0o040755,
        uid: int = 0,
        gid: int = 0,
        dev: int = 0,
    ):
        super().__init__(name=virt_path, mode=mode, uid=uid, gid=gid, dev=dev)
        self.host_path = host_path
        self.mount_table = mount_table

    def lookup(self, name: str) -> Optional[VfsNode]:
        if name in self.children:
            return self.children[name]

        child_host = os.path.join(self.host_path, name)
        if not os.path.exists(child_host):
            return None

        child_virt = posixpath.join(self.name, name)
        mp = self.mount_table.find_mount(child_virt)

        if os.path.isdir(child_host):
            node = HostDirNode(
                virt_path=child_virt,
                host_path=child_host,
                mount_table=self.mount_table,
                mode=mp.dir_mode,
                uid=mp.default_uid,
                gid=mp.default_gid,
                dev=mp.dev
            )
        else:
            node = HostFileNode(
                virt_path=child_virt,
                host_path=child_host,
                mode=mp.file_mode,
                uid=mp.default_uid,
                gid=mp.default_gid,
                dev=mp.dev
            )

        node.setxattr("security.selinux", mp.selinux_context)

        self.children[name] = node

        return node

    def getdents(self) -> List[Tuple[str, int, int]]:
        entries = super().getdents()
        existing_names = {e[0] for e in entries}

        if os.path.exists(self.host_path):
            try:
                with os.scandir(self.host_path) as it:
                    for entry in it:
                        if entry.name not in existing_names:
                            entry_ino = zlib.adler32(f"{self.name}/{entry.name}".encode()) & 0xFFFFFFFF
                            d_type = DT_DIR if entry.is_dir(follow_symlinks=False) else (DT_LNK if entry.is_symlink() else DT_REG)
                            entries.append((entry.name, d_type, entry_ino))
            except OSError:
                pass
        return entries