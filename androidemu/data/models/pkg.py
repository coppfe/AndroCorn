from dataclasses import dataclass, field
import random
import time
from typing import Optional, List
from .device import Device


@dataclass
class Pkg:
    pkg_name: str
    version_name: str = "1.0.0"
    version_code: int = 1
    
    uid: int = field(default_factory=lambda: random.randint(10000, 10999))
    pid: int = field(default_factory=lambda: random.randint(10000, 20000))
    ppid: int = field(default_factory=lambda: random.randint(500, 1200))

    start_timestamp: int = field(default_factory=lambda: int(time.time()))
    first_install_time: int = field(default_factory=lambda: int(time.time()) - 86400 * 30)
    last_update_time: int = field(default_factory=lambda: int(time.time()) - 86400 * 5)
    
    debuggable: bool = False
    sign_hex: Optional[str] = None
    permissions: List[str] = field(default_factory=lambda: [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE"
    ])
    
    device: Device = field(default_factory=Device)

    def __post_init__(self):
        if isinstance(self.device, dict):
            self.device = Device(**self.device)