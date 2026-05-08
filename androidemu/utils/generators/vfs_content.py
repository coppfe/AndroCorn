import os
import re
import random
import struct
import io

from ...const import emu_const
from ...const.templates import STATUS_TEMPLATE
from ...const.linux import *

from typing import TYPE_CHECKING, Optional, Callable, Dict, Any

if TYPE_CHECKING:
    from ...emulator import Emulator

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

    def __init__(self, emulator: 'Emulator'):
        self.__emu: 'Emulator' = emulator
        
        self.cfg = emulator.config
        self.pcb = emulator.pcb
        self.memory_map = emulator.memory
        
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
            re.compile(r'^/sys/devices/system/cpu/online$'):    self._gen_cpu_online,
            re.compile(r'^/proc/(self|\d+)/fd/\d+$'):           self._gen_fd_link,
            re.compile(r'^/dev/u?random$'):                     self._dev_urandom,
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
            fds = self.pcb.virtual_files.get_all_fds() 
            return [str(fd) for fd in fds]

        if re.match(r'^/proc/(self|\d+)$', virt_path):
            return [
                "status", "maps", "cmdline", "cgroup", "stat", 
                "statm", "environ", "fd", "task", "auxv"
            ]

        if virt_path == "/proc":
            return ["self", "stat", "version", "uptime", "meminfo", "net", str(self.pcb.pid)]

        return ["."]

    def _gen_status(self, **kwargs):
        self._sim_vol_switches += random.randint(1, 5)
        self._sim_nonvol_switches += random.randint(0, 1)

        vm_size_kb = random.randint(100000, 200000) 

        return STATUS_TEMPLATE.format(
            pkg_name=self.cfg.pkg.pkg_name,
            pid=self.pcb.pid,
            ppid=self.cfg.pkg.ppid,
            uid=self.pcb.uid,
            vm_peak=vm_size_kb + 1024,
            vm_size=vm_size_kb,
            vm_hwm=vm_size_kb,
            vm_rss=vm_size_kb // 2,
            vm_data=vm_size_kb // 3,
            vm_stk=8192,
            vm_lib=32000,
            vm_pte=512,
            threads=self.pcb.get_threads(),
            cpus_mask="ff",
            cpus_max=7,
            vol_switches=self._sim_vol_switches,
            nonvol_switches=self._sim_nonvol_switches
        )

    def _gen_exe(self, count, **kwargs):
        app_process_path = self.__emu.vfs_root + "/system/bin/" + ("app_process32" if self.__emu.arch == emu_const.ARCH_ARM32 else "app_process64")
        with open(app_process_path, "rb") as f:
            return f.read(count)

    def _gen_maps(self, **kwargs):
        buf = io.StringIO()
        modules = self.__emu.linker.modules
        regions = self.__emu.mu.mem_regions()
        
        for start, end, prot in regions:
            r = 'r' if prot & 4 else '-'
            w = 'w' if prot & 2 else '-'
            x = 'x' if prot & 1 else '-'
            p = 'p' 
            flags = "%s%s%s%s" % (r, w, x, p)

            path = ""
            for mod in modules:
                if mod.base <= start < (mod.base + mod.size):
                    path = mod.filename
                    break
            
            if path:
                path = path.replace("vfs//", "/")
                if not path.startswith("/"):
                    path = "/" + path
            
            if not path:
                if start >= 0xff000000:
                    path = "[stack]"
                elif start == 0xffff0000:
                    path = "[vectors]"
                # elif start == 0xf7e22000: path = "[vvar]"
                # elif start == 0xf7e25000: path = "[vdso]"

            line = "%08X-%08X %s 00000000 00:00 0"% (start, end, flags)

            if path:
                line = line.ljust(73) + path
                
            buf.write(line + "\n")
        return buf.getvalue()
    
    def _gen_fd_link(self, virt_path: str, **kwargs):
        try:
            fd_num = int(virt_path.split('/')[-1])
            vfile = self.pcb.virtual_files.get_fd_detail(fd_num)
            if vfile:
                return vfile.name
        except (ValueError, IndexError):
            pass
        return None
    
    def _gen_cmdline(self, **kwargs):
        return "%s\x00"%self.cfg.pkg.pkg_name
    
    def _gen_cpu_online(self, **kwargs):
        return "0-7\n"

    def _gen_cgroup(self, **kwargs):
        return "2:cpu:/\n1:cpuacct:/\n"

    def _dev_urandom(self, count, **kwargs):
        return os.urandom(count)

    def _dev_virtual(self, **kwargs):
        return None