import logging
from typing import TYPE_CHECKING, List
from ....cli.engine import VirtualCLIEngine

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

class ExecveHandler:
    def __init__(self):
        self.cli = None

    def execute(self, emu: 'Emulator', filename: str, argv: List[str]) -> int:
        logging.debug("[Execve] Executing: %s %s", filename, argv)

        if self.cli is None:
            self.cli = VirtualCLIEngine(emu)

        cmd_name = filename.split("/")[-1]
        exit_code = 0
        output = ""

        if cmd_name == "sh":
            try:
                c_idx = argv.index("-c")
                command_line = argv[c_idx + 1]
                exit_code, output = self.cli.execute_command_line(command_line)
            except (ValueError, IndexError):
                exit_code, output = 1, "sh: syntax error\n"

        elif cmd_name in self.cli.commands:
            cmd_obj = self.cli.commands[cmd_name]
            exit_code, output = cmd_obj.run(argv[1:])

        else:
            exit_code, output = 127, f"{filename}: not found\n"

        if output:
            emu.vfs.write(1, output.encode("utf-8"))

        emu.vfs.close(1)

        return exit_code