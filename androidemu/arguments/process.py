from dataclasses import dataclass, field

from typing import TYPE_CHECKING

from androidemu.core.state._global import GlobalContextMachine

if TYPE_CHECKING:
    from androidemu.core.process.pcb import ProcessControlBlock
    from androidemu.cpu.scheduler import Scheduler
    from androidemu.utils.memory.map import MemoryMap
    from androidemu.utils.tls import BionicTLSUtils
    from unicorn import Uc
    from androidemu import Emulator

@dataclass
class ProcessArgumentsBlock:
    emu: 'Emulator'
    mu: 'Uc'
    memory: 'MemoryMap'
    control_block: 'ProcessControlBlock'
    scheduler: 'Scheduler'
    tls: 'BionicTLSUtils'
    ctx: 'GlobalContextMachine' = field(default_factory=GlobalContextMachine)