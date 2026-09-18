from dataclasses import dataclass, field
from .memory import Memory
from .kernel import Kernel
from .net import Net
from .hardware import CPUInfo, GPUInfo
from .display import DisplayInfo
from .system import BatteryInfo, TelephonyInfo, BuildInfo, SettingsSecure


@dataclass
class Device:
    build: BuildInfo = field(default_factory=BuildInfo)
    cpu: CPUInfo = field(default_factory=CPUInfo)
    gpu: GPUInfo = field(default_factory=GPUInfo)
    display: DisplayInfo = field(default_factory=DisplayInfo)
    battery: BatteryInfo = field(default_factory=BatteryInfo)
    telephony: TelephonyInfo = field(default_factory=TelephonyInfo)
    network: Net = field(default_factory=Net)
    memory: Memory = field(default_factory=Memory)
    kernel: Kernel = field(default_factory=Kernel)
    secure: SettingsSecure = field(default_factory=SettingsSecure)

    def __post_init__(self):
        converters = {
            "build": BuildInfo,
            "cpu": CPUInfo,
            "gpu": GPUInfo,
            "display": DisplayInfo,
            "battery": BatteryInfo,
            "telephony": TelephonyInfo,
            "network": Net,
            "memory": Memory,
            "kernel": Kernel,
            "secure": SettingsSecure,
        }
        for field_name, cls in converters.items():
            val = getattr(self, field_name)
            if isinstance(val, dict):
                setattr(self, field_name, cls(**val))