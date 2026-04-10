import platform
from random import randint
from typing import Dict, List, Optional, TYPE_CHECKING

g_isWin = platform.system() == "Windows"
if not g_isWin:
    import fcntl

from ...objects.virtual_file import VirtualFile

if TYPE_CHECKING:
    from ...emulator import Emulator

class VirtualFileTable:
    def __init__(self, emulator: 'Emulator'):

        self.__emu: 'Emulator' = emulator
        
        self._virtual_files: Dict[int, VirtualFile] = {}
        self._fds: Dict[int, VirtualFile] = {}

        self.add_fd("stdin", "/dev/stdin", 0)
        self.add_fd("stdout", "/dev/stdout", 1)
        self.add_fd("stderr", "/dev/stderr", 2)

        self.__next_virtual_fd = 1000

    def add_fd(self, name: str, name_in_system: str, fd: int, is_virtual: bool = False) -> int:
        self._fds[fd] = VirtualFile(self.__emu, name, fd, name_in_system=name_in_system, is_virtual=is_virtual)
        return fd
    
    def add_virtual_fd(self, name: str, name_in_system: str) -> int:
        fd = self.__next_virtual_fd
        self.__next_virtual_fd += 1
        return self.add_fd(name, name_in_system, fd, is_virtual=True)

    def get_fd_detail(self, fd: int) -> Optional[VirtualFile]:
        return self._fds.get(fd)
    
    def create_virtual_file(self, name: str, name_in_system: str, fd: int, is_virtual: bool = False) -> int:
        vf = VirtualFile(self.__emu, name, fd, name_in_system=name_in_system, is_virtual=is_virtual)
        return vf
    
    def has_fd(self, fd: int) -> bool:
        return fd in self._fds
    
    def remove_fd(self, fd: int) -> None:
        if fd in self._fds:
            self._fds.pop(fd)

    def is_virtual_fd(self, fd: int) -> bool:
        if fd not in self._fds: return False
        vfile = self._fds[fd]
        return getattr(vfile, 'name_in_system', '').startswith("VIRTUAL:")

    def get_virtual_name(self, fd: int) -> Optional[str]:
        if not self.is_virtual_fd(fd): return None
        return self._fds[fd].name_in_system.replace("VIRTUAL:", "")
    
    def get_all_fds(self) -> List[VirtualFile]:
        return list(self._fds.values())