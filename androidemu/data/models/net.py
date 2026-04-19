from dataclasses import dataclass

@dataclass
class Net:
    ip: str = "192.168.1.52"
    mac: str = "cc:fa:a6:00:8a:a9"
    dns: str = "8.8.8.8"
    ssid: str = "Massive"
    gateway: str = "89.207.132.170"