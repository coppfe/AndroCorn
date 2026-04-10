from dataclasses import dataclass, field

from typing import Any, Dict

import random

from .memory import Memory
from .kernel import Kernel
from .net import Net

@dataclass
class Device:
    android_id: str = field(default_factory=lambda: ''.join(random.choice('0123456789abcdef') for _ in range(16)))
    
    memory: Memory = field(init=False)
    kernel: Kernel = field(init=False)
    net: Net       = field(init=False)

    memory: Any = field(default_factory=dict) 
    kernel: Any = field(default_factory=dict)
    net: Any    = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.memory, dict):
            self.memory = Memory(**self.memory)
        if isinstance(self.kernel, dict):
            self.kernel = Kernel(**self.kernel)
        if isinstance(self.net, dict):
            self.net = Net(**self.net)