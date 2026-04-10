from dataclasses import dataclass, field

import random
import time

from typing import Optional
from .device import Device

@dataclass
class Pkg:
    _pkg_name: str
    pkg_name: str
    uid: int = field(default_factory=lambda: random.randint(10000, 20000))
    pid: int = field(default_factory=lambda: random.randint(10000, 20000))
    ppid: int = field(default_factory=lambda: random.randint(10000, 20000))
    
    debuggable: bool = False
    start_timestamp: int = field(default_factory=lambda: int(time.time()))
    build_at: int = 1678884069
    sign_hex: Optional[str] = None
    version_code: Optional[int] = None
    
    device: Device = field(default_factory=Device)

    def __post_init__(self):
        if isinstance(self.device, dict):
            self.device = Device(**self.device)