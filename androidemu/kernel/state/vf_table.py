import os
import logging

from typing import Dict, List, Optional, TYPE_CHECKING

from ...objects.virtual_file import VirtualFile

if TYPE_CHECKING:
    from ...emulator import Emulator

logging.getLogger(__name__)

class VirtualFileTable:
    def __init__(self, emulator: 'Emulator'):
        self.__emu: 'Emulator' = emulator
        
        self._tid_to_fds: Dict[int, Dict[int, VirtualFile]] = {}
        
        self.__next_virtual_fd = 1000

        main_pid = self.__emu.pcb.pid
        self._tid_to_fds[main_pid] = {}

        self.add_fd("stdin", "/dev/stdin", 0)
        self.add_fd("stdout", "/dev/stdout", 1)
        self.add_fd("stderr", "/dev/stderr", 2)

    @property
    def _fds(self) -> Dict[int, VirtualFile]:
        tid = self.__emu.pcb.current_tid
        if tid not in self._tid_to_fds:
            self._tid_to_fds[tid] = {}
        return self._tid_to_fds[tid]

    def clone_for_task(self, parent_tid, child_tid, share_table=False):
        if parent_tid not in self._tid_to_fds:
            self._tid_to_fds[parent_tid] = {}
        
        parent_table = self._tid_to_fds[parent_tid]

        if share_table:
            self._tid_to_fds[child_tid] = parent_table
        else:
            new_table = {}
            for fd_num, vf in parent_table.items():
                new_table[fd_num] = vf
                vf.ref_count += 1
            self._tid_to_fds[child_tid] = new_table

    def remove_task(self, tid: int):
        if tid in self._tid_to_fds:
            table = self._tid_to_fds[tid]
            
            is_shared = any(t != tid and self._tid_to_fds[t] is table for t in self._tid_to_fds)
            
            if not is_shared:
                for fd_num in list(table.keys()):
                    vf = table.pop(fd_num)
                    vf.close() 
            
            del self._tid_to_fds[tid]

    def add_fd(self, name: str, name_in_system: str, fd: int, is_virtual: bool = False) -> int:
        self._fds[fd] = VirtualFile(self.__emu, name, fd, name_in_system=name_in_system, is_virtual=is_virtual)
        return fd
    
    def add_virtual_fd(self, name: str, name_in_system: str) -> int:
        fd = self.__next_virtual_fd
        self.__next_virtual_fd += 1
        return self.add_fd(name, name_in_system, fd, is_virtual=True)

    def get_fd_detail(self, fd: int) -> Optional[VirtualFile]:
        return self._fds.get(fd)
    
    def create_virtual_file(self, name: str, name_in_system: str, fd: int, is_virtual: bool = False) -> VirtualFile:
        vf = VirtualFile(self.__emu, name, fd, name_in_system=name_in_system, is_virtual=is_virtual)
        return vf
    
    def has_fd(self, fd: int) -> bool:
        return fd in self._fds
    
    def remove_fd(self, fd: int) -> None:
        if fd in self._fds:
            vf = self._fds.pop(fd)
            vf.close() 

    def is_virtual_fd(self, fd: int) -> bool:
        if fd not in self._fds: return False
        vfile = self._fds[fd]
        return getattr(vfile, 'name_in_system', '').startswith("VIRTUAL:")

    def get_virtual_name(self, fd: int) -> Optional[str]:
        if not self.is_virtual_fd(fd): return None
        return self._fds[fd].name_in_system.replace("VIRTUAL:", "")
    
    def get_fd_by_name(self, name: str) -> Optional[int]:
        for fd, vf in self._fds.items():
            if vf.name == name:
                return fd
    
    def get_all_fds(self) -> List[VirtualFile]:
        return list(self._fds.values())