import re
import logging

from ......const.linux import *

from typing import Dict, List, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from ......emulator import Emulator

class ExecveHandler:
    def __init__(self, emulator: 'Emulator'):
        self.__emu: 'Emulator' = emulator
        self.pcb = emulator.pcb
        
        self.commands: Dict[str, Callable] = {
            "pm": self._handle_pm,
            "getprop": self._handle_getprop,
            "id": self._handle_id,
            "sh": self._handle_sh,
        }

    def write_stdout(self, msg: str):
        pipe_out = self.pcb.virtual_files.get_fd_detail(1)
        pipe_out.write(msg.encode())

    def execute(self, filename: str, argv: List[str]) -> int:
        """
        filename: binary path
        """
        cmd_name = filename.split('/')[-1]
        
        if not cmd_name and len(argv) > 0:
            cmd_name = argv[0].split('/')[-1]

        logging.debug("[*] Execve hit: %s | Args: %s", filename, argv)

        res = -1
        if cmd_name in self.commands:
            res = self.commands[cmd_name](argv)

        if self.pcb.virtual_files.has_fd(1):
            self.pcb.virtual_files.remove_fd(1)
            
        return res
    
    def _handle_pm(self, argv: List[str]) -> int:
        cmd_line = " ".join(argv)
        match = re.search(r'path (?P<pkg>[\w\.]+)', cmd_line)
        if match:
            return self._logic_pm_path(match.group('pkg'))
        return 0

    def _handle_sh(self, argv: List[str]) -> int:
        try:
            c_idx = argv.index("-c")
            shell_cmd = argv[c_idx + 1]
        except (ValueError, IndexError):
            logging.error("sh called without -c or missing command")
            return -EPERM

        shell_cmd = shell_cmd.strip("'\"")
        return self._dispatch_shell_command(shell_cmd)
    
    def _handle_getprop(self, argv: List[str]) -> int:
        prop_name = argv[1] if len(argv) > 1 else ""
        return self._logic_getprop(prop_name)
    
    def _handle_id(self, argv: List[str]) -> int:
        logging.debug("[EXECVE MOCK] id -> uid=%d", self.pcb.uid)
        return 0

    def _dispatch_shell_command(self, cmd_line: str) -> int:
        patterns = [
            (r'^pm path (?P<pkg>[\w\.]+)', self._logic_pm_path),
            (r'^getprop (?P<prop>[\w\.]+)', self._logic_getprop),
            (r'^am get-config', self._logic_am_get_config),
            (r'^ps\s+(-e\s+)?\|\s+grep\s+adbd', self._logic_ps_grep_adbd),
        ]

        for pattern, logic_func in patterns:
            match = re.match(pattern, cmd_line)
            if match:
                return logic_func(**match.groupdict())

        logging.warning("[-] Shell command '%s' not recognized by any regex.", cmd_line)
        self.write_stdout("")
        return 0

    def _logic_pm_path(self, pkg: str) -> int:
        if pkg == self.__emu.config.pkg.pkg_name:
            path_res = "package:/data/app/%s-1/base.apk\n" % pkg
            self.write_stdout(path_res)
            logging.debug("[EXECVE MOCK] Output: %s", path_res.strip())
        return 0

    def _logic_getprop(self, prop: str) -> int:
        val = self.__emu.system_properties.get(prop, "\n")
        self.write_stdout(val)
        logging.debug("[EXECVE MOCK] getprop %s -> %s", prop, val)
        return 0
    
    def _logic_am_get_config(self) -> int:
        config_res = self.__emu.config.pkg.device.config
        self.write_stdout(config_res)
        logging.debug("[EXECVE MOCK] am get-config sent.")
        return 0
    
    def _logic_ps_grep_adbd(self, **kwargs) -> int:
        logging.info("[EXECVE MOCK] hiding adbd process.")
        
        self.write_stdout("") 
        return 1