from typing import Dict

from abc import ABC, abstractmethod

class StubAddress(ABC):

    global_func_table: Dict[str, int] = {}

    @abstractmethod
    def __init__(self):
        pass