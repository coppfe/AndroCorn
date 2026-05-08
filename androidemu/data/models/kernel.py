from dataclasses import dataclass

@dataclass
class Kernel:
    sysname:    str = "Linux"
    nodename:   str = "localhost"
    release:    str = "3.18.31-g427242c"
    domain:     str = "localdomain"
    version:    str = "#1 SMP PREEMPT Thu Mar 09 11:20:45 UTC 2017"