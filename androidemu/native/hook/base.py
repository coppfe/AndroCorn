from typing import List, Callable, Tuple, Optional

from abc import ABC, abstractmethod

class HookAddress(ABC):

    global_func_table: List[Tuple[str, int, Callable, Optional[Callable]]] = []

    @abstractmethod
    def __init__(self):
        pass