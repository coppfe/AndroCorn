import os
import posixpath
import struct
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from .node import VfsNode, VirtualDirNode, RootVfsNode
from .nodes.devices import (
    DevNullNode, DevUrandomNode, TtyNode, BinderNode,
    MemoryFileNode, PtmxNode, DevPtsDirNode
)
from .nodes.host import HostFileNode, HostDirNode
from .nodes.proc import ProcRootNode, SysCpuOnlineNode
from ...const.linux import O_RDONLY, O_WRONLY, O_NOFOLLOW, AT_FDCWD, EBADF, ENOENT, EINVAL, EEXIST
from .mounts import create_default_mount_table, MountTable

if TYPE_CHECKING:
    from ...core.emulator import Emulator


class FileHandle:
    __slots__ = ("node", "flags", "offset", "ref_count")

    def __init__(self, node: VfsNode, flags: int):
        self.node = node
        self.flags = flags
        self.offset = 0
        self.ref_count = 1

    def close(self) -> bool:
        self.ref_count -= 1
        return self.ref_count <= 0


class VFSManager:
    MAX_SYMLINKS = 40

    def __init__(self, emu: 'Emulator'):
        self.emu = emu
        self.vfs_root = emu.vfs_root
        self.tm = emu.time_manager
        self.ctx = emu.pcb
        self.config = emu.config

        self._tid_fds: Dict[int, Dict[int, FileHandle]] = {}
        self._next_fd = 100

        self.mount_table: MountTable = create_default_mount_table(self.config.pkg.uid)

        host_root = HostDirNode("/", self.vfs_root, self.mount_table, dev=(259 << 8) | 0)
        self.root_node = RootVfsNode(host_dir_node=host_root)

        self._init_system_mounts()
        self._init_stdio(self.ctx.pid)

    def _init_system_mounts(self):
        self.mount("/proc", ProcRootNode(self))

        self.mount("/dev/null", DevNullNode())
        self.mount("/dev/zero", DevNullNode())
        self.mount("/dev/urandom", DevUrandomNode())
        self.mount("/dev/random", DevUrandomNode())
        self.mount("/dev/binder", BinderNode())
        self.mount("/dev/ashmem", DevNullNode())
        self.mount("/dev/tty", TtyNode("/dev/tty"))
        
        self.mount("/dev/ptmx", PtmxNode())
        self.mount("/dev/pts", DevPtsDirNode(self))

        self.mount("/sys/devices/system/cpu/online", SysCpuOnlineNode())

    def _init_stdio(self, tid: int):
        self._tid_fds[tid] = {
            0: FileHandle(TtyNode("stdin"), O_RDONLY),
            1: FileHandle(TtyNode("stdout"), O_WRONLY),
            2: FileHandle(TtyNode("stderr"), O_WRONLY),
        }

    def mount(self, virt_path: str, node: VfsNode) -> VfsNode:
        norm = posixpath.normpath(virt_path).strip("/")
        if not norm:
            self.root_node = node  # type: ignore
            return node

        parts = norm.split("/")
        curr: VfsNode = self.root_node

        for i, part in enumerate(parts[:-1]):
            nxt = curr.lookup(part)
            if nxt is None or not nxt.is_dir:
                new_dir = VirtualDirNode(name="/" + "/".join(parts[:i + 1]))
                if isinstance(curr, VirtualDirNode):
                    curr.add_child(part, new_dir)
                curr = new_dir
            else:
                curr = nxt

        if isinstance(curr, VirtualDirNode):
            curr.add_child(parts[-1], node)
        return node

    def mount_file(self, virt_path: str, host_path: str, uid: Optional[int] = None, gid: Optional[int] = None, dev: Optional[int] = None) -> HostFileNode:
        if not os.path.exists(host_path):
            raise FileNotFoundError(f"Host file not found: {host_path}")

        norm = posixpath.normpath(virt_path)
        if not norm.startswith("/"):
            norm = "/" + norm

        mp = self.mount_table.find_mount(norm)
        node = HostFileNode(
            virt_path=norm,
            host_path=os.path.abspath(host_path),
            uid=uid if uid is not None else mp.default_uid,
            gid=gid if gid is not None else mp.default_gid,
            dev=dev if dev is not None else mp.dev,
            mode=mp.file_mode
        )
        node.setxattr("security.selinux", mp.selinux_context)
        self.mount(norm, node)
        return node

    def mount_data(self, virt_path: str, data: bytes, mode: int = 0o100644, uid: int = 0, gid: int = 0) -> MemoryFileNode:
        norm = posixpath.normpath(virt_path)
        if not norm.startswith("/"):
            norm = "/" + norm
        node = MemoryFileNode(norm, data, mode=mode, uid=uid, gid=gid)
        self.mount(norm, node)
        return node

    def resolve_node(self, dirfd: int, path: str, follow_symlinks: bool = True) -> Optional[VfsNode]:
        if not path:
            if dirfd == AT_FDCWD:
                return None
            handle = self.get_handle(dirfd)
            if not handle:
                return None
            node = handle.node
            if follow_symlinks and node.is_symlink:
                target = node.readlink()
                if target:
                    return self.get_node(target, follow_symlinks=True)
            return node

        if path.startswith("/") or dirfd == AT_FDCWD:
            start_node = self.root_node
            rel_path = path
        else:
            handle = self.get_handle(dirfd)
            if not handle or not handle.node.is_dir:
                return None
            start_node = handle.node
            rel_path = path

        norm = posixpath.normpath(rel_path)
        return self._walk_path(start_node, norm, follow_symlinks)

    def get_node(self, virt_path: str, follow_symlinks: bool = True) -> Optional[VfsNode]:
        if not virt_path:
            return None
        norm = posixpath.normpath(virt_path)
        return self._walk_path(self.root_node, norm, follow_symlinks)

    def _walk_path(self, start_node: VfsNode, path: str, follow_symlinks: bool) -> Optional[VfsNode]:
        components = [c for c in path.split("/") if c and c != "."]
        curr = start_node
        symlinks_followed = 0

        for i, comp in enumerate(components):
            is_last = (i == len(components) - 1)

            if not curr.is_dir:
                return None

            next_node = curr.lookup(comp)
            if next_node is None:
                return None

            if next_node.is_symlink and (not is_last or follow_symlinks):
                if symlinks_followed >= self.MAX_SYMLINKS:
                    return None  # -ELOOP

                target = next_node.readlink()
                if not target:
                    return None
                symlinks_followed += 1

                remaining = components[i + 1:]
                if target.startswith("/"):
                    target_path = posixpath.join(target, *remaining)
                else:
                    target_path = posixpath.join(curr.name, target, *remaining)
                return self._walk_path(self.root_node, target_path, follow_symlinks)

            curr = next_node

        return curr

    def openat(self, dirfd: int, path: str, flags: int, mode: int) -> int:
        follow = not bool(flags & O_NOFOLLOW)
        node = self.resolve_node(dirfd, path, follow_symlinks=follow)
        if not node:
            return -ENOENT

        perm_err = node.check_permission(self.ctx, flags)
        if perm_err != 0:
            return perm_err

        return self.create_fd_for_node(node, flags)
    
    def readlink(self, dirfd: int, path: str) -> Optional[str]:
        if not path and dirfd != AT_FDCWD:
            handle = self.get_handle(dirfd)
            if not handle:
                return None
            return handle.node.readlink()

        node = self.resolve_node(dirfd, path, follow_symlinks=False)
        if not node or not node.is_symlink:
            return None
        return node.readlink()

    def stat(self, dirfd: int, path: str, follow_symlinks: bool = True):
        node = self.resolve_node(dirfd, path, follow_symlinks=follow_symlinks)
        if not node:
            return None
        return node.stat(self.tm)

    def fstat(self, fd: int):
        handle = self.get_handle(fd)
        if not handle:
            return None
        stat = handle.node.stat(self.tm)
        return stat
    def close(self, fd: int) -> int:
        fds = self._get_current_fds()
        handle = fds.pop(fd, None)
        if not handle:
            return -EBADF
        handle.close()
        return 0

    def read(self, fd: int, count: int) -> Tuple[int, bytes]:
        handle = self.get_handle(fd)
        if not handle:
            return -EBADF, b""
        data = handle.node.read(handle.offset, count)
        handle.offset += len(data)
        return len(data), data

    def write(self, fd: int, data: bytes) -> int:
        handle = self.get_handle(fd)
        if not handle:
            return -EBADF
        written = handle.node.write(handle.offset, data)
        if written > 0:
            handle.offset += written
        return written

    def lseek(self, fd: int, offset: int, whence: int) -> int:
        handle = self.get_handle(fd)
        if not handle:
            return -EBADF

        if whence == 0:
            handle.offset = offset
        elif whence == 1:
            handle.offset += offset
        elif whence == 2:
            handle.offset = handle.node.get_size() + offset

        if handle.offset < 0:
            handle.offset = 0
        return handle.offset

    def ioctl(self, fd: int, cmd: int, arg: int, mu) -> int:
        handle = self.get_handle(fd)
        if not handle:
            return -EBADF
        return handle.node.ioctl(cmd, arg, mu)

    def mkdir(self, dirfd: int, path: str, mode: int = 0o040755) -> int:
        if not path:
            return -EINVAL

        if path.startswith("/") or dirfd == AT_FDCWD:
            start_node = self.root_node
            rel_path = path
        else:
            handle = self.get_handle(dirfd)
            if not handle or not handle.node.is_dir:
                return -EBADF
            start_node = handle.node
            rel_path = path

        norm = posixpath.normpath(rel_path).strip("/")
        if not norm:
            return -EEXIST

        parts = norm.split("/")
        curr: VfsNode = start_node

        for i, part in enumerate(parts[:-1]):
            nxt = curr.lookup(part)
            if nxt is None or not nxt.is_dir:
                new_dir = VirtualDirNode(name="/" + "/".join(parts[:i + 1]), mode=mode, uid=self.ctx.uid, gid=self.ctx.gid)
                if isinstance(curr, VirtualDirNode):
                    curr.add_child(part, new_dir)
                curr = new_dir
            else:
                curr = nxt

        target_name = parts[-1]
        
        existing = curr.lookup(target_name)
        if existing is not None:
            return -EEXIST

        if isinstance(curr, VirtualDirNode):
            full_path = posixpath.join(curr.name if curr.name != "/" else "", target_name)
            if not full_path.startswith("/"):
                full_path = "/" + full_path
                
            new_dir_node = VirtualDirNode(name=full_path, mode=mode, uid=self.ctx.uid, gid=self.ctx.gid)
            curr.add_child(target_name, new_dir_node)
            return 0

        return -EINVAL

    def getdents64(self, fd: int, count: int) -> Tuple[int, bytes]:
        handle = self.get_handle(fd)
        if not handle:
            return -EBADF, b""

        entries = handle.node.getdents()
        if not entries or handle.offset >= len(entries):
            return 0, b""

        buf = bytearray()
        cur_idx = handle.offset

        while cur_idx < len(entries):
            name, d_type, d_ino = entries[cur_idx]
            name_bytes = name.encode("utf-8") + b"\x00"

            reclen = (8 + 8 + 2 + 1 + len(name_bytes) + 7) & ~7
            if len(buf) + reclen > count:
                break

            padding = reclen - (8 + 8 + 2 + 1 + len(name_bytes))
            packed_header = struct.pack("<QqHB", d_ino, cur_idx + 1, reclen, d_type)

            buf += packed_header
            buf += name_bytes
            buf += b"\x00" * padding
            cur_idx += 1

        handle.offset = cur_idx
        return len(buf), bytes(buf)

    def clone_task(self, parent_tid: int, child_tid: int, share_table: bool = False):
        parent_table = self._tid_fds.get(parent_tid, {})
        if share_table:
            self._tid_fds[child_tid] = parent_table
            return

        new_table = {}
        for fd, handle in parent_table.items():
            new_table[fd] = handle
            handle.ref_count += 1
        self._tid_fds[child_tid] = new_table

    def remove_task(self, tid: int):
        table = self._tid_fds.get(tid)
        if not table:
            return
        is_shared = any(t != tid and self._tid_fds[t] is table for t in self._tid_fds)
        if not is_shared:
            for handle in table.values():
                handle.close()
        del self._tid_fds[tid]

    def create_fd_for_node(self, node: VfsNode, flags: int = 0, specific_fd: Optional[int] = None) -> int:
        fd = specific_fd if specific_fd is not None else self._next_fd
        if specific_fd is None:
            self._next_fd += 1
        handle = FileHandle(node, flags)
        self._get_current_fds()[fd] = handle
        return fd

    def _get_current_fds(self) -> Dict[int, FileHandle]:
        tid = self.ctx.current_tid
        if tid not in self._tid_fds:
            self._tid_fds[tid] = {}
        return self._tid_fds[tid]

    def get_handle(self, fd: int) -> Optional[FileHandle]:
        return self._get_current_fds().get(fd)

    def get_current_task_fds(self) -> List[int]:
        return list(self._get_current_fds().keys())