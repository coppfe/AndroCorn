from typing import TYPE_CHECKING


from .vf_table import VirtualFileTable

if TYPE_CHECKING:
    from ...data.config import Config
    from unicorn import Uc
    from androidemu.core.state._global import GlobalContextMachine
    from androidemu.data.states.process import ProcessState

class ProcessControlBlock:
    """
    Have all info about process. Here is stored a virtual file table worker
    """
    def __init__(self, mu: 'Uc', cfg: 'Config', ctx: 'GlobalContextMachine') -> None:
        self._cfg = cfg

        proc_ctx: 'ProcessState' = ctx # type: ignore

        proc_ctx.pid            =   cfg.pkg.pid
        proc_ctx.ppid           =   cfg.pkg.ppid
        proc_ctx.uid            =   cfg.pkg.uid
        proc_ctx.gid            =   cfg.pkg.uid

        proc_ctx.current_tid    =   cfg.pkg.pid
        proc_ctx.threads        =   {proc_ctx.current_tid}
        
        proc_ctx.process_name   =   cfg.pkg.pkg_name
        proc_ctx.dumpable       =   0
        proc_ctx.ptrace         =   0
        proc_ctx.sigactions     =   dict()

        self.virtual_files = VirtualFileTable(mu, ctx)