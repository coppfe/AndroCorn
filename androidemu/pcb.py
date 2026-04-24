from random import randint
from typing import Dict, List, TYPE_CHECKING

from .utils.state.vf_table import VirtualFileTable

if TYPE_CHECKING:
    from .config import Config
    from .emulator import Emulator

class Pcb:
    """
    Pcb - Process Control Block

    Have all info about process
    """
    def __init__(self, emulator: 'Emulator', cfg: 'Config') -> None:
        self._cfg = cfg
        self.__emu: 'Emulator' = emulator

        self._pid = cfg.pkg.pid if cfg.pkg.pid != -1 else randint(10000, 20000)
        self._ppid = cfg.pkg.ppid # Zygote
        self._uid = cfg.pkg.uid
        self._gid = self._uid

        self._main_tid = self._pid # PID == Main TID
        self._current_tid = self._main_tid
        self._next_tid_counter = self._pid + 1
        
        self._threads = {self._main_tid}
        
        self._uc_to_tid = {} 

    def post_init(self):
        """
        Post Init for methods with recursive dependency
        """
        self.virtual_files = VirtualFileTable(self.__emu)
        
    @property
    def pid(self) -> int:
        return self._pid
    
    @property
    def ppid(self) -> int:
        return self._ppid
    
    @property
    def uid(self) -> int:
        return self._uid
    
    @property
    def gid(self) -> int:
        return self._gid
    
    @property
    def current_tid(self) -> int:
        return self._current_tid

    @property
    def main_tid(self) -> int:
        return self._main_tid
        
    @property
    def next_tid_counter(self) -> int:
        return self._next_tid_counter
    
    @property
    def threads(self) -> List[int]:
        return list(self._threads)
    
    @property
    def uc_to_tid(self) -> Dict[int, int]:
        return self._uc_to_tid

    # def assign_main_tid(self, uc_instance):
    #     self._uc_to_tid[uc_instance] = self._main_tid
    #     return self._main_tid

    def generate_new_tid(self) -> int:
        tid = self._next_tid_counter
        self._next_tid_counter += 1
        self._threads.add(tid)
        return tid

    # def register_thread_uc(self, uc_instance, tid: int):
    #     self._uc_to_tid[uc_instance] = tid
    #     self._threads.add(tid)

    # def unregister_thread(self, tid: int):
    #     if tid in self._threads:
    #         self._threads.remove(tid)
    #     keys_to_del = [k for k, v in self._uc_to_tid.items() if v == tid]
    #     for k in keys_to_del:
    #         del self._uc_to_tid[k]

    # def get_tid_by_uc(self, uc_instance) -> int:
    #     return self._uc_to_tid.get(uc_instance, self._main_tid)

    def get_threads(self) -> List[int]:
        return list(self._threads)