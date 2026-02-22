from typing import TYPE_CHECKING, List, Callable, Tuple, Optional

from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from ...emulator import Emulator

class BaseFuncHooks(ABC):

    global_func_table: List[Tuple[str, int, Callable, Optional[Callable]]] = []

    @abstractmethod
    def __init__(self, emu: 'Emulator'):
        pass