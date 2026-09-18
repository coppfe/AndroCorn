from typing import Dict, Set, Tuple, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.data.config import Config

class ProcessControlBlock:
    """Process Context
    
    Attributes:
        pid (int): Process ID.
        ppid (int): Parent Process ID.
        uid (int): User ID of the process owner.
        gid (int): Group ID of the process owner.
        current_tid (int): Currently executing thread ID.
        threads (Set[int]): Set of active thread IDs associated with the process.
        process_name (str): Package or binary process name.
        dumpable (int): Process core dump flag (e.g., PR_SET_DUMPABLE state).
        ptrace (Any): Ptrace tracing state or attached tracer identifier.
        sigactions (Dict[int, Tuple[int, int, int, int]]): Signal action handlers map
            indexed by signal number.
        altstack (Tuple[int, int, int]): Alternate signal stack parameters (ss_sp, ss_flags, ss_size).
    """

    __slots__ = (
        "pid", "ppid", "uid", "gid",
        "current_tid", "threads",
        "process_name", "dumpable", "ptrace",
        "sigactions", "altstack"
    )

    def __init__(self, cfg: 'Config'):
        self.pid: int = cfg.pkg.pid
        self.ppid: int = cfg.pkg.ppid
        self.uid: int = cfg.pkg.uid
        self.gid: int = cfg.pkg.uid
        self.current_tid: int = cfg.pkg.pid
        self.threads: Set[int] = {self.current_tid}
        self.process_name: str = cfg.pkg.pkg_name
        self.dumpable: int = 1
        self.ptrace: Any = 0
        self.sigactions: Dict[int, Tuple[int, int, int, int]] = {}
        self.altstack: Tuple[int, int, int] = (0, 2, 0)