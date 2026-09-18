from typing import List, Tuple, Dict
from .engine import Command

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...data.config import Config

class UnameCommand(Command):
    def __init__(self, config: 'Config', arch: int = 2):
        self.config = config
        self.kernel = config.pkg.device.kernel
        self.arch = arch

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        # arch: 1 = ARM32, 2 = ARM64
        machine = "armv8l" if self.arch == 1 else "aarch64"
        sysname = getattr(self.kernel, 'sysname', 'Linux')
        nodename = getattr(self.kernel, 'nodename', 'localhost')
        release = getattr(self.kernel, 'release', '4.14.180-g9b389a9')
        version = getattr(self.kernel, 'version', '#1 SMP PREEMPT 2021')

        if not args:
            return 0, f"{sysname}\n"

        if "-a" in args or "--all" in args:
            return 0, f"{sysname} {nodename} {release} {version} {machine}\n"

        res = []
        if "-s" in args or "--kernel-name" in args:
            res.append(sysname)
        if "-n" in args or "--nodename" in args:
            res.append(nodename)
        if "-r" in args or "--kernel-release" in args:
            res.append(release)
        if "-v" in args or "--kernel-version" in args:
            res.append(version)
        if "-m" in args or "--machine" in args:
            res.append(machine)

        if res:
            return 0, " ".join(res) + "\n"

        return 0, f"{sysname}\n"


class GetpropCommand(Command):
    def __init__(self, properties: Dict[str, str]):
        self.properties = properties

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        if not args:
            lines = [f"[{k}]: [{v}]" for k, v in self.properties.items()]
            return 0, "\n".join(lines) + "\n"

        key = args[0]
        val = self.properties.get(key, "")
        return 0, f"{val}\n" if val else "\n"


class PmCommand(Command):
    def __init__(self, config: 'Config'):
        self.config = config

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        if len(args) >= 2 and args[0] == "path":
            pkg = args[1]
            if pkg == self.config.pkg.pkg_name:
                return 0, f"package:/data/app/{pkg}-1/base.apk\n"
        return 1, "\n"


class AmCommand(Command):
    def __init__(self, config: 'Config'):
        self.config = config

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        if args and args[0] == "get-config":
            return 0, f"{self.config.pkg.device.display.to_am_config()}\n"
        return 0, "\n"


class IdCommand(Command):
    def __init__(self, ctx):
        self.ctx = ctx

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        uid = self.ctx.uid
        pkg = getattr(self.ctx, 'process_name', 'app')
        return 0, f"uid={uid}({pkg}) gid={uid}({pkg}) groups={uid}({pkg})\n"


class WhichCommand(Command):
    def __init__(self, allowed_bins: List[str] = None):
        self.allowed = allowed_bins or ["sh", "pm", "am", "getprop", "id", "ps", "cat"]

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        if not args:
            return 1, ""
        target = args[0]
        if target in self.allowed:
            return 0, f"/system/bin/{target}\n"
        return 1, ""


class PsCommand(Command):
    def __init__(self, config, ctx):
        self.config = config
        self.ctx = ctx

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        out = (
            "USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
            f"u0_a{self.ctx.uid%1000:<4}  {self.ctx.pid:<5} {self.config.pkg.ppid:<5} 1234560 123450 0                   0 S {self.config.pkg.pkg_name}\n"
        )
        return 0, out


class CatCommand(Command):
    def __init__(self, vfs):
        self.vfs = vfs

    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        if not args:
            return 0, stdin
        target_path = args[0]
        node = self.vfs.get_node(self.vfs.resolve_path(0, target_path))
        if node:
            content = node.read(0, node.get_size() or 65536)
            return 0, content.decode("utf-8", errors="ignore")
        return 1, f"cat: {target_path}: No such file or directory\n"


class GrepCommand(Command):
    def run(self, args: List[str], stdin: str = "") -> Tuple[int, str]:
        if not args:
            return 0, stdin

        pattern = args[-1].strip("'\"")
        invert = "-v" in args

        matching_lines = []
        for line in stdin.splitlines():
            matched = pattern in line
            if (matched and not invert) or (not matched and invert):
                matching_lines.append(line)

        res = "\n".join(matching_lines) + ("\n" if matching_lines else "")
        return (0 if matching_lines else 1), res