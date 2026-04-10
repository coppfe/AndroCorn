from dataclasses import dataclass

@dataclass
class Kernel:
    sysname:    str = "Linux"
    nodename:   str = "localhost"
    release:    str = "5.10.43-android12-9-00001-g532147395026"
    domain:     str = "localdomain"
    version:    str = "#1 SMP PREEMPT Wed Mar 15 12:41:09 UTC 2023"