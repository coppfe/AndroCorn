import bisect
import os
from typing import List, Tuple, Optional, TYPE_CHECKING

from ..node import VfsNode, VirtualDirNode
from ....data import layout
from ....const.linux import DT_LNK, DT_DIR
from ....const.templates import STATUS_TEMPLATE, MOUNTINFO
from ...selinux.policy import SELinuxPolicy
from ..vdstat import VirtualDeviceStat

if TYPE_CHECKING:
    from androidemu.core.pcb import ProcessControlBlock
    from androidemu.data.config import Config
    from ....internal.linker import AndroidLinker
    from ....utils.memory.map import MemoryMap
    from ..manager import VFSManager


class ProcSelfSymlinkNode(VfsNode):

    def __init__(self, vfs: 'VFSManager'):
        super().__init__(name="/proc/self", mode=0o120777, uid=0, gid=0, dev=0x000C)
        self.vfs = vfs
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

    def readlink(self) -> Optional[str]:
        return str(self.vfs.ctx.pid)


class ProcFdLinkNode(VfsNode):

    def __init__(self, fd: int, vfs_manager: 'VFSManager'):
        super().__init__(name=f"/proc/self/fd/{fd}", mode=0o120777, uid=0, gid=0, dev=0x000C)
        self.fd = fd
        self.vfs = vfs_manager
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

    def readlink(self) -> Optional[str]:
        handle = self.vfs.get_handle(self.fd)
        if not handle:
            return None
        target = handle.node.name
        return target if target.startswith("/") else f"/{target}"


class ProcFdDirNode(VirtualDirNode):

    def __init__(self, pid: int, vfs_manager: 'VFSManager'):
        super().__init__(name=f"/proc/{pid}/fd", mode=0o040555, uid=0, gid=0, dev=0x000C)
        self.pid = pid
        self.vfs = vfs_manager
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

    def lookup(self, name: str) -> Optional[VfsNode]:
        if name.isdigit():
            fd_num = int(name)
            if self.vfs.get_handle(fd_num) is not None:
                return ProcFdLinkNode(fd_num, self.vfs)
        return None

    def getdents(self) -> List[Tuple[str, int, int]]:
        entries = [
            (".", DT_DIR, self.ino),
            ("..", DT_DIR, (self.ino ^ 0xFFFF) & 0xFFFFFFFF)
        ]
        for fd in self.vfs.get_current_task_fds():
            fd_ino = (self.ino + fd) & 0xFFFFFFFF
            entries.append((str(fd), DT_LNK, fd_ino))
        return entries


class ProcPidDirNode(VirtualDirNode):

    def __init__(self, pid: int, vfs: 'VFSManager'):
        super().__init__(name=f"/proc/{pid}", mode=0o040555, uid=0, gid=0, dev=0x000C)
        self.pid = pid
        self.vfs = vfs
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

        self.add_child("maps", ProcMapsNode(vfs.emu.memory, vfs.emu.linker, vfs))
        self.add_child("status", ProcStatusNode(vfs.ctx, vfs.config))
        self.add_child("cmdline", ProcCmdlineNode(vfs.config))
        self.add_child("mountinfo", ProcMountinfoNode())
        self.add_child("fd", ProcFdDirNode(pid, vfs))


class ProcRootNode(VirtualDirNode):

    def __init__(self, vfs: 'VFSManager'):
        super().__init__(name="/proc", mode=0o040555, uid=0, gid=0, dev=0x000C)
        self.vfs = vfs
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

        self.add_child("self", ProcSelfSymlinkNode(vfs))
        self.add_child("cpuinfo", ProcCpuinfoNode())
        self.add_child("mountinfo", ProcMountinfoNode())

    def lookup(self, name: str) -> Optional[VfsNode]:
        child = self.children.get(name)
        if child is not None:
            return child

        if name.isdigit():
            target_pid = int(name)
            if target_pid == self.vfs.ctx.pid or target_pid in getattr(self.vfs.ctx, "threads", set()):
                return ProcPidDirNode(target_pid, self.vfs)

        return None


class ProcMapsNode(VfsNode):
    def __init__(self, memory_map: 'MemoryMap', linker: 'AndroidLinker', vfs: 'VFSManager'):
        pid = vfs.ctx.pid if (vfs and vfs.ctx) else 1000
        proc_ino = ((pid << 16) | 3) & 0xFFFFFFFF
        
        super().__init__(
            name=f"/proc/{pid}/maps", 
            mode=0o100444, 
            uid=0, 
            gid=0, 
            dev=0x000C,
            ino=proc_ino
        )
        self.memory_map = memory_map
        self.linker = linker
        self.vfs = vfs
        self.vfs_root = vfs.vfs_root
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)
        self._cached_maps = ""
        self._last_gen = -1

    def read(self, offset: int, count: int) -> bytes:
        data = self._generate_maps().encode("utf-8")
        return data[offset:offset + count]

    def _format_dev(self, dev_num: int) -> str:
        major = (dev_num >> 8) & 0xFFF
        minor = dev_num & 0xFF
        return f"{major:02x}:{minor:02x}"

    def _generate_maps(self) -> str:
        current_gen = getattr(self.memory_map, 'map_generation', 0)
        if self._cached_maps and self._last_gen == current_gen and self._last_gen != -1:
            return self._cached_maps

        file_intervals = []
        for mod in getattr(self.linker, 'modules', []):
            mod_size = getattr(mod, 'size', 0)
            file_intervals.append((mod.base, mod.base + mod_size, 0, mod.filename))

        for start_addr, (end_addr, f_offset, vf) in getattr(self.memory_map, '_file_map_addr', {}).items():
            vf_name = getattr(vf, 'name', '')
            file_intervals.append((start_addr, end_addr, f_offset, vf_name))

        file_intervals.sort(key=lambda x: x[0])
        file_starts = [x[0] for x in file_intervals]

        maps_lines = []
        heap_already_named = False

        for start, end, prot in self.memory_map.get_regions():
            if any(hidden_base <= start < (hidden_base + 0x1000000) for hidden_base in layout.HIDE):
                continue
            page_end = end + 1 if (end & 0xFFF) == 0xFFF else end
            r = "r" if (prot & 1) else "-"
            w = "w" if (prot & 2) else "-"
            x = "x" if (prot & 4) else "-"
            prot_str = f"{r}{w}{x}p"

            pathname = ""
            offset = 0
            dev_str = "00:00"
            inode = 0

            idx = bisect.bisect_right(file_starts, start) - 1
            if idx >= 0:
                f_start, f_end, f_offset, f_name = file_intervals[idx]
                if start < f_end:
                    pathname = f_name
                    if pathname.startswith(self.vfs_root):
                        pathname = "/" + os.path.relpath(pathname, self.vfs_root)
                    pathname = pathname.replace("../", "").replace("..", "")

                    if "[vectors]" in pathname:
                        continue

                    offset = f_offset + (start - f_start)

                    node = self.vfs.get_node(pathname, follow_symlinks=False)
                    if node:
                        dev_str = self._format_dev(node.dev)
                        inode = node.ino

            if not pathname:
                is_stack = (
                    (layout.STACK_ADDR <= start < layout.STACK_ADDR + layout.STACK_SIZE) or
                    (layout.CHILD_STACK_ADDR <= start < layout.CHILD_STACK_ADDR + layout.STACK_SIZE)
                )
                is_heap = (layout.BRK_BASE <= start < layout.BRK_BASE + layout.BRK_SIZE)

                if is_stack:
                    pathname = "[stack]"
                elif is_heap and not heap_already_named:
                    pathname = "[heap]"
                    heap_already_named = True

            if pathname:
                line = f"{start:08x}-{page_end:08x} {prot_str} {offset:08x} {dev_str} {inode:<8} {pathname}"
            else:
                line = f"{start:08x}-{page_end:08x} {prot_str} {offset:08x} {dev_str} {inode}"

            maps_lines.append(line)

        outbuf = "\n".join(maps_lines) + "\n"
        self._cached_maps = outbuf
        self._last_gen = current_gen
        return outbuf


class ProcStatusNode(VfsNode):
    def __init__(self, ctx: 'ProcessControlBlock', config: 'Config'):
        pid = ctx.pid if ctx else 1000
        proc_ino = ((pid << 16) | 2) & 0xFFFFFFFF
        
        super().__init__(
            name=f"/proc/{pid}/status", 
            mode=0o100444, 
            uid=0, 
            gid=0, 
            dev=0x000C,
            ino=proc_ino
        )
        self.ctx = ctx
        self.config = config
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

    def stat(self, time_manager) -> VirtualDeviceStat:
        start_us = getattr(self.ctx, 'start_timestamp', 1678884069) * 1_000_000
        return VirtualDeviceStat(
            st_mode=self.mode,
            st_size=0,
            st_blocks=0,
            st_blksize=1024,
            st_ino=self.ino,
            st_dev=self.dev,
            st_rdev=0,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            atime_us=start_us,
            mtime_us=start_us,
            ctime_us=start_us
        )

    def _render_content(self) -> bytes:
        vm_size_kb = 145000
        content = STATUS_TEMPLATE.format(
            pkg_name=self.config.pkg.pkg_name,
            pid=self.ctx.pid,
            ppid=self.config.pkg.ppid,
            tracerpid=0,
            uid=self.ctx.uid,
            vm_peak=vm_size_kb + 1024,
            vm_size=vm_size_kb,
            vm_hwm=vm_size_kb,
            vm_rss=vm_size_kb // 2,
            vm_data=vm_size_kb // 3,
            vm_stk=8192,
            vm_lib=32000,
            vm_pte=512,
            threads=len(self.ctx.threads) if hasattr(self.ctx, 'threads') and self.ctx.threads else 1,
            cpus_mask="ff",
            cpus_max=7,
            vol_switches=350,
            nonvol_switches=20
        )
        return content.encode("utf-8")

    def get_size(self) -> int:
        return 0

    def read(self, offset: int, count: int) -> bytes:
        data = self._render_content()
        if offset >= len(data):
            return b""
        return data[offset:offset + count]
    
class ProcCmdlineNode(VfsNode):
    """/proc/self/cmdline"""

    def __init__(self, config: 'Config'):
        super().__init__(name="/proc/self/cmdline", mode=0o100444, uid=0, gid=0, dev=0x000C)
        self.config = config
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

    def read(self, offset: int, count: int) -> bytes:
        return f"{self.config.pkg.pkg_name}\x00".encode("utf-8")[offset:offset + count]


class ProcMountinfoNode(VfsNode):
    """/proc/self/mountinfo"""

    def __init__(self):
        super().__init__(name="/proc/self/mountinfo", mode=0o100444, uid=0, gid=0, dev=0x000C)
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

    def read(self, offset: int, count: int) -> bytes:
        return MOUNTINFO.encode("utf-8")[offset:offset + count]


class ProcCpuinfoNode(VfsNode):
    """/proc/cpuinfo"""

    def __init__(self):
        super().__init__(name="/proc/cpuinfo", mode=0o100444, uid=0, gid=0, dev=0x000C)
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_PROC)

    def read(self, offset: int, count: int) -> bytes:
        content = (
            "processor\t: 0\n"
            "BogoMIPS\t: 38.40\n"
            "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n"
            "CPU implementer\t: 0x51\n"
            "CPU architecture: 8\n"
            "CPU variant\t: 0x2\n"
            "CPU part\t: 0x205\n"
            "CPU revision\t: 1\n\n"
        ).encode("utf-8")
        return content[offset:offset + count]


class SysCpuOnlineNode(VfsNode):
    """/sys/devices/system/cpu/online"""

    def __init__(self):
        super().__init__(name="/sys/devices/system/cpu/online", mode=0o100444, uid=0, gid=0, dev=0x000B)
        self.setxattr("security.selinux", SELinuxPolicy.CONTEXT_SYSFS)

    def read(self, offset: int, count: int) -> bytes:
        return b"0-7\n"[offset:offset + count]