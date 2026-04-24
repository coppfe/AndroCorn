from typing import Dict, List, Optional, TYPE_CHECKING

from ...objects.virtual_file import VirtualFile

if TYPE_CHECKING:
    from ...emulator import Emulator


# =========================
# SYMLINK LAYER (Linux-like)
# =========================

class Symlink:
    __slots__ = ("target",)

    def __init__(self, target: str):
        self.target = target

    def read(self) -> str:
        return self.target


class SymlinkTable:
    def __init__(self):
        self._links: dict[str, Symlink] = {}

    # -------------------------
    # SETTERS
    # -------------------------
    def create(self, path: str, target: str):
        self._links[path] = Symlink(target)

    def remove(self, path: str):
        self._links.pop(path, None)

    # -------------------------
    # GETTERS
    # -------------------------
    def exists(self, path: str) -> bool:
        return path in self._links

    def readlink(self, path: str) -> Optional[str]:
        link = self._links.get(path)
        return link.read() if link else None


# =========================
# FD TABLE (process scoped)
# =========================

class VirtualFileTable:
    def __init__(self, emulator: 'Emulator'):
        self.__emu = emulator

        self._tid_to_fds: Dict[int, Dict[int, VirtualFile]] = {}

        self.__next_virtual_fd = 1000

        self.symlinks = SymlinkTable()

        main_pid = self.__emu.pcb.pid
        self._tid_to_fds[main_pid] = {}

        self._init_std_fds()

    # =========================
    # INIT
    # =========================
    def _init_std_fds(self):
        self.add_fd("stdin", "/dev/stdin", 0)
        self.add_fd("stdout", "/dev/stdout", 1)
        self.add_fd("stderr", "/dev/stderr", 2)

    # =========================
    # FD LAYER - PROPERTY
    # =========================
    @property
    def _fds(self) -> Dict[int, VirtualFile]:
        tid = self.__emu.pcb.current_tid
        if tid not in self._tid_to_fds:
            self._tid_to_fds[tid] = {}
        return self._tid_to_fds[tid]

    # =========================
    # FD LAYER - SETTERS
    # =========================
    def add_fd(self, name: str, name_in_system: str, fd: int, is_virtual: bool = False) -> int:
        self._fds[fd] = VirtualFile(
            self.__emu,
            name,
            fd,
            name_in_system=name_in_system,
            is_virtual=is_virtual
        )
        return fd

    def add_virtual_fd(self, name: str, name_in_system: str) -> int:
        fd = self.__next_virtual_fd
        self.__next_virtual_fd += 1
        return self.add_fd(name, name_in_system, fd, is_virtual=True)

    def remove_fd(self, fd: int) -> None:
        vf = self._fds.pop(fd, None)
        if vf:
            vf.close()

    # =========================
    # FD LAYER - GETTERS
    # =========================
    def has_fd(self, fd: int) -> bool:
        return fd in self._fds

    def get_fd_detail(self, fd: int) -> Optional[VirtualFile]:
        return self._fds.get(fd)

    def get_all_fds(self) -> List[VirtualFile]:
        return list(self._fds.values())

    def get_fd_by_name(self, name: str) -> Optional[int]:
        for fd, vf in self._fds.items():
            if vf.name == name:
                return fd

    # =========================
    # SYMLINK LAYER - SETTERS
    # =========================
    def add_symlink(self, path: str, target: str) -> None:
        self.symlinks.create(path, target)

    def remove_symlink(self, path: str) -> None:
        self.symlinks.remove(path)

    # =========================
    # SYMLINK LAYER - GETTERS
    # =========================
    def get_symlink_target(self, path: str) -> Optional[str]:
        return self.symlinks.readlink(path)

    # =========================
    # PROCESS LIFECYCLE
    # =========================
    def clone_for_task(self, parent_tid: int, child_tid: int, share_table: bool = False):
        parent_table = self._tid_to_fds.get(parent_tid, {})

        if share_table:
            self._tid_to_fds[child_tid] = parent_table
            return

        new_table = {}
        for fd, vf in parent_table.items():
            new_table[fd] = vf
            vf.ref_count += 1

        self._tid_to_fds[child_tid] = new_table

    def remove_task(self, tid: int):
        table = self._tid_to_fds.get(tid)
        if not table:
            return

        is_shared = any(
            t != tid and self._tid_to_fds[t] is table
            for t in self._tid_to_fds
        )

        if not is_shared:
            for vf in table.values():
                vf.close()

        del self._tid_to_fds[tid]

    # =========================
    # OBJECT CREATORS
    # =========================
    def create_virtual_file(self, name: str, name_in_system: str, fd: int, is_virtual: bool = False) -> VirtualFile:
        vf = VirtualFile(self.__emu, name, fd, name_in_system=name_in_system, is_virtual=is_virtual)
        return vf