import sys
import logging
from random import randint
from typing import Dict, List, Optional, TYPE_CHECKING

from .objects.virtual_file import VirtualFile 

if TYPE_CHECKING:
    from .config import Config

class Pcb:
    def __init__(self, cfg: 'Config') -> None:
        self._cfg = cfg
        
        self._pid = randint(10000, 15000) 
        self._ppid = cfg.get("ppid", 821) # Zygote
        
        self._uid = cfg.get("uid", 10000) 
        self._gid = self._uid
        
        self._main_tid = self._pid # PID == Main TID
        self._next_tid_counter = self._pid + 1
        
        self._threads = {self._main_tid}
        
        self._uc_to_tid = {} 

        self._fds: Dict[int, VirtualFile] = {}
        self._fds[0] = VirtualFile('stdin', 0, name_in_system='/dev/stdin')
        self._fds[1] = VirtualFile('stdout', 1, name_in_system='/dev/stdout')
        self._fds[2] = VirtualFile('stderr', 2, name_in_system='/dev/stderr')

        self.voluntary_switches = randint(100, 500)
        self.nonvoluntary_switches = randint(10, 50)

        self.sig_blk = 0
        self.sig_ign = 0
        self._current_tid = self._main_tid

    @property
    def pid(self) -> int:
        return self._pid

    def get_pid(self) -> int:
        return self._pid

    def get_ppid(self) -> int:
        return self._ppid
    
    @property
    def uid(self) -> int:
        return self._uid

    def get_uid(self) -> int:
        return self._uid
    
    def get_gid(self) -> int:
        return self._gid


    def assign_main_tid(self, uc_instance):
        self._uc_to_tid[uc_instance] = self._main_tid
        return self._main_tid

    def generate_new_tid(self) -> int:
        tid = self._next_tid_counter
        self._next_tid_counter += 1
        self._threads.add(tid)
        return tid

    def register_thread_uc(self, uc_instance, tid: int):
        self._uc_to_tid[uc_instance] = tid
        self._threads.add(tid)

    def unregister_thread(self, tid: int):
        if tid in self._threads:
            self._threads.remove(tid)
        keys_to_del = [k for k, v in self._uc_to_tid.items() if v == tid]
        for k in keys_to_del:
            del self._uc_to_tid[k]

    def get_tid_by_uc(self, uc_instance) -> int:
        return self._uc_to_tid.get(uc_instance, self._main_tid)

    def get_threads(self) -> List[int]:
        return list(self._threads)

    def add_fd(self, name: str, name_in_system: str, fd: int) -> int:
        self._fds[fd] = VirtualFile(name, fd, name_in_system=name_in_system)
        return fd

    def get_fd_detail(self, fd: int) -> Optional[VirtualFile]:
        return self._fds.get(fd)
    
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