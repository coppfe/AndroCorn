import shlex
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ...core.emulator import Emulator

class Command(ABC):
    @abstractmethod
    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        pass


class VirtualCLIEngine:
    def __init__(self, emu: 'Emulator'):
        self._emu = emu

        self.commands: Dict[str, Command] = {}
        self._register_default_commands()

    def register(self, name: str, cmd: Command) -> None:
        self.commands[name] = cmd

    def _register_default_commands(self):
        from .builtins import (
            GetpropCommand, PmCommand, AmCommand, IdCommand,
            WhichCommand, PsCommand, CatCommand, UnameCommand, GrepCommand
        )
        self.register("getprop", GetpropCommand(self._emu.system_properties))
        self.register("pm", PmCommand(self._emu.config))
        self.register("am", AmCommand(self._emu.config))
        self.register("id", IdCommand(self._emu.pcb))
        self.register("which", WhichCommand())
        self.register("ps", PsCommand(self._emu.config, self._emu.pcb))
        self.register("cat", CatCommand(self._emu.vfs))
        self.register("uname", UnameCommand(self._emu.config))
        self.register("grep", GrepCommand())

    def execute_command_line(self, cmd_line: str) -> Tuple[int, str]:
        pipeline = [part.strip() for part in cmd_line.split("|")]
        
        current_stdin = ""
        exit_code = 0

        for stage in pipeline:
            try:
                tokens = shlex.split(stage)
            except ValueError:
                tokens = stage.split()

            if not tokens:
                continue

            cmd_name = tokens[0].split("/")[-1]
            args = tokens[1:]

            if cmd_name in self.commands:
                cmd_obj = self.commands[cmd_name]
                exit_code, current_stdin = cmd_obj.run(args, stdin=current_stdin)
            else:
                return 127, f"sh: {cmd_name}: not found\n"

        return exit_code, current_stdin