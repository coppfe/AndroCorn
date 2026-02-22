from typing import TYPE_CHECKING, Dict, Tuple

from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from ...emulator import Emulator

class BaseSymbolHooks(ABC):

    global_func_table: Dict[str, int] = {}

    @abstractmethod
    def __init__(self, emu: 'Emulator'):
        pass