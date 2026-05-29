import                                  os
import                                  re
import                                  zlib  
import                                  random
import                                  struct
import                                  bisect

from ...const.linux                     import *       
from ...const                           import emu_const
from ...const.templates                 import STATUS_TEMPLATE, MOUNTINFO
from ...data                            import mem_map

from unicorn                            import UC_PROT_READ, UC_PROT_EXEC, UC_PROT_WRITE

from ...utils                           import misc_utils

from typing                             import TYPE_CHECKING, Optional, Callable, Dict, Any

if TYPE_CHECKING:
    from androidemu.arguments.process       import ProcessArgumentsBlock
    from androidemu.arguments.system        import SystemArgumentsBlock
    from androidemu.data.states.process     import ProcessState

class Helpers:
    def __init__(self):
        pass

    @staticmethod
    def _align8(x: int) -> int:
        return (x + 7) & ~7

    def _serialize_dirents(self, entries: list):
        """
        entries: List[str] | List[Tuple[name, type]]
        """
        buf = bytearray()
        offset = 0

        for entry in entries:
            if isinstance(entry, tuple):
                name, d_type = entry
            else:
                name = entry
                d_type = DT_UNKNOWN

            name_bytes = name.encode() + b'\x00'

            reclen = 8 + 8 + 2 + 1 + len(name_bytes)  # fields + name
            reclen = self._align8(reclen)

            padding = reclen - (8 + 8 + 2 + 1 + len(name_bytes))

            packed = struct.pack(
                "<QqHB",   # little-endian
                1,         # d_ino fake
                offset,    # d_off
                reclen,
                d_type
            )

            buf += packed
            buf += name_bytes
            buf += b'\x00' * padding

            offset += reclen

        return bytes(buf)

class ContentGenerator(Helpers):

    def __init__(self, process: 'ProcessArgumentsBlock', system: 'SystemArgumentsBlock'):
        
        
        self._sys = system
        self._proc = process

        self._cache = {}
        self._last_gen = -1

        self._cfg = system.config
        self._pcb = process.control_block
        self._memory_map = process.memory

        self._sim_vol_switches = random.randint(100, 1000)
        self._sim_nonvol_switches = random.randint(10, 100)

        self.routes: Dict[str, Callable] = {
            re.compile(r'^/proc$'):                             self._gen_dir,
            re.compile(r'^/proc/(self|\d+)$'):                  self._gen_dir,
            re.compile(r'^/proc/(self|\d+)/fd$'):               self._gen_dir,
            re.compile(r'^/proc/(self|\d+)/status$'):           self._gen_status,
            re.compile(r'^/proc/(self|\d+)/exe$'):              self._gen_exe,
            re.compile(r'^/proc/(self|\d+)/maps$'):             self._gen_maps,
            re.compile(r'^/proc/(self|\d+)/cmdline$'):          self._gen_cmdline,
            re.compile(r'^/proc/(self|\d+)/cgroup$'):           self._gen_cgroup,
            re.compile(r'^/proc/(self|\d+)/mountinfo$'):        self._gen_mountinfo,
            re.compile(r'^/sys/devices/system/cpu/online$'):    self._gen_cpu_online,
            re.compile(r'^/proc/(self|\d+)/fd/\d+$'):           self._gen_fd_link,
            re.compile(r'^/dev/u?random$'):                     self._dev_urandom,
            re.compile(r'^/dev/socket/.*'):                     self._dev_virtual,
            re.compile(r'^/dev/(null|binder)$'):                self._dev_virtual,
            re.compile(r'std(in|out|err)$'):                    self._dev_virtual,
        }

    def _find_handler(self, virt_path: str) -> Optional[Callable]:
        for pattern, h in self.routes.items():
            if re.match(pattern, virt_path):
                return h
        return None

    def is_virtual(self, virt_path: str) -> bool:
        return self._find_handler(virt_path) is not None

    def resolve_dir_entries(self, virt_path: str, host_path: str, **kwargs) -> Optional[bytes]:
        """
        Generating directory content
        """
        handler = self._find_handler(virt_path)

        if handler:
            content = handler(virt_path=virt_path, **kwargs)

            if content is None:
                return None

            if isinstance(content, bytes):
                return content

            return self._serialize_dirents(content)

        if os.path.isdir(host_path):
            entries = os.listdir(host_path)
            return self._serialize_dirents(entries)

        return None

    def generate(self, virt_path: str, **kwargs) -> Optional[Any]:
        handler = self._find_handler(virt_path)
        if not handler:
            return None
        return handler(virt_path=virt_path, **kwargs)

    def _gen_dir(self, virt_path: str, **kwargs):

        if "fd" in virt_path:
            fds = self._pcb.virtual_files.get_all_fds()
            return [str(fd) for fd in fds]

        if re.match(r'^/proc/(self|\d+)$', virt_path):
            return [
                "status", "maps", "cmdline", "cgroup", "stat",
                "statm", "environ", "fd", "task", "auxv"
            ]

        if virt_path == "/proc":
            ctx: 'ProcessState' = self._proc.ctx
            return ["self", "stat", "version", "uptime", "meminfo", "net", str(ctx.pid)]

        return ["."]

    def _gen_status(self, **kwargs):
        self._sim_vol_switches += random.randint(1, 5) # bad?
        self._sim_nonvol_switches += random.randint(0, 1) # bad?
        
        vm_size_kb = random.randint(100000, 200000)

        ctx: 'ProcessState' = self._proc.ctx

        return STATUS_TEMPLATE.format(
            pkg_name=self._cfg.pkg.pkg_name,
            pid=ctx.pid,
            ppid=self._cfg.pkg.ppid,
            tracerpid=ctx.ptrace,
            uid=ctx.uid,
            vm_peak=vm_size_kb + 1024,
            vm_size=vm_size_kb,
            vm_hwm=vm_size_kb,
            vm_rss=vm_size_kb // 2,
            vm_data=vm_size_kb // 3,
            vm_stk=8192,
            vm_lib=32000,
            vm_pte=512,
            threads=ctx.threads,
            cpus_mask="ff",
            cpus_max=7,
            vol_switches=self._sim_vol_switches,
            nonvol_switches=self._sim_nonvol_switches
        )

    def _gen_exe(self, count, **kwargs):
        app_process_path = self._sys.mount + "/system/bin/" + ("app_process32" if self._sys.arch == emu_const.ARCH_ARM32 else "app_process64")
        with open(app_process_path, "rb") as f:
            return f.read(count)

    def _gen_maps(self, **kwargs):
        current_gen = self._memory_map.map_generation
        cached = self._cache.get("maps", None)
        
        if cached and self._last_gen != -1:
            return cached
        
        DEV = "00:0c"
        
        file_intervals = []
        for mod in self._sys.linker.modules:
            mod_size = getattr(mod, 'size', 0)
            file_intervals.append((mod.base, mod.base + mod_size, 0, mod.filename))

        for start_addr, (end_addr, offset, vf) in self._memory_map._file_map_addr.items():
            file_intervals.append((start_addr, end_addr, offset, vf.name))

        file_intervals.sort(key=lambda x: x[0])
        file_starts = [x[0] for x in file_intervals]

        hide_rules = mem_map.HIDE
        has_complex_rules = isinstance(hide_rules, list) and len(hide_rules) > 0 and isinstance(hide_rules[0], tuple)
        simple_hide_set = set(hide_rules) if not has_complex_rules and isinstance(hide_rules, list) else set()

        maps_lines = []

        for start, end, prot in self._memory_map.get_regions():
            is_hidden = False
            
            if has_complex_rules:
                for h_start, h_end in hide_rules:
                    if not (end <= h_start or start >= h_end):
                        is_hidden = True
                        break
            elif start in simple_hide_set:
                is_hidden = True

            if is_hidden: 
                continue

            r = "r" if (prot & UC_PROT_READ) else "-"
            w = "w" if (prot & UC_PROT_WRITE) else "-"
            x = "x" if (prot & UC_PROT_EXEC) else "-"
            prot_str = f"{r}{w}{x}p"

            offset = 0
            dev_str = "00:00"
            inode = 0
            pathname = ""

            idx = bisect.bisect_right(file_starts, start) - 1
            if idx >= 0:
                f_start, f_end, f_offset, f_name = file_intervals[idx]
                if start < f_end:
                    pathname = misc_utils.system_path_to_vfs_path(self._sys.mount, f_name)
                    offset = f_offset + (start - f_start)
                    
                    if pathname == "[vectors]":
                        dev_str = "00:00"
                        inode = 0
                    else:
                        dev_str = DEV
                        inode = zlib.adler32(pathname.encode()) & 0xFFFFFFFF

            if not pathname:
                is_stack = (
                    (mem_map.STACK_ADDR <= start < mem_map.STACK_ADDR + mem_map.STACK_SIZE) or
                    (mem_map.CHILD_STACK_ADDR <= start < mem_map.CHILD_STACK_ADDR + mem_map.STACK_SIZE)
                )
                is_heap = (mem_map.MAP_ALLOC_BASE <= start < mem_map.MAP_ALLOC_BASE + mem_map.MAP_ALLOC_SIZE)

                if is_stack:
                    pathname = "[stack]"
                elif is_heap:
                    pathname = ""

            if not pathname or pathname in ("[stack]", "[heap]", "[vectors]"):
                dev_str = "00:00"
                inode = 0
                if pathname != "[vectors]":
                    offset = 0

            line = f"{start:08x}-{end:08x} {prot_str} {offset:08x} {dev_str} {inode:<10} {pathname}".strip()
            maps_lines.append(line)

        outbuf = "\n".join(maps_lines) + "\n"
        self._cache.update({"maps": outbuf})

        self._last_gen = current_gen
        
        return outbuf

    def _gen_mountinfo(self, **kwargs):
        return MOUNTINFO.encode("utf-8")

    def _gen_fd_link(self, virt_path: str, **kwargs):
        try:
            fd_num = int(virt_path.split('/')[-1])
            vfile = self._pcb.virtual_files.get_fd_detail(fd_num)
            if vfile:
                return vfile.name
        except (ValueError, IndexError):
            pass
        return None

    def _gen_cmdline(self, **kwargs):
        return "%s\x00"%self._cfg.pkg.pkg_name

    def _gen_cpu_online(self, **kwargs):
        return "0-7\n"

    def _gen_cgroup(self, **kwargs):
        return "2:cpu:/\n1:cpuacct:/\n"

    def _dev_urandom(self, count, **kwargs):
        return os.urandom(count)

    def _dev_virtual(self, **kwargs):
        return None