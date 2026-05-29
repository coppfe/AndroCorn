from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Dict

if TYPE_CHECKING:
    from androidemu.data.config import Config
    from androidemu.core.state.time_manager import TimeManager
    from androidemu.objects.registers import RegistersMapping
    from androidemu.internal.linker import AndroidLinker


@dataclass
class SystemArgumentsBlock:
    arch: Literal[1, 2]
    mount: str # vfs_root
    config: 'Config'
    clock: 'TimeManager'
    registers: 'RegistersMapping'
    linker:    'AndroidLinker'
    properties: Dict[str, str] = field(default_factory=dict)
