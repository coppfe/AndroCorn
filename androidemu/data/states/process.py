from typing import Dict, Tuple

class ProcessState:
    pid: int
    ppid: int
    uid: int
    gid: int
    current_tid: int
    threads: Dict[int]
    process_name: str
    dumpable:     int
    ptrace:       int
    sigactions:   Dict[int, Tuple[int, int, int, int]]