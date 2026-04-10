import os
import re
import random
import logging
import io

from ...const import emu_const

from typing import TYPE_CHECKING, Tuple, Optional, Callable, Dict, Any

if TYPE_CHECKING:
    from ...emulator import Emulator

STATUS_TEMPLATE = """
Name:\t{pkg_name}
State:\tR (running)
Tgid:\t{pid}
Pid:\t{pid}
PPid:\t{ppid}
TracerPid:\t0
Uid:\t{uid}\t{uid}\t{uid}\t{uid}
Gid:\t{uid}\t{uid}\t{uid}\t{uid}
FDSize:\t256
Groups:\t3003 9997 20123 50123
VmPeak:\t{vm_peak} kB
VmSize:\t{vm_size} kB
VmLck:\t0 kB
VmPin:\t0 kB
VmHWM:\t{vm_hwm} kB
VmRSS:\t{vm_rss} kB
VmData:\t{vm_data} kB
VmStk:\t{vm_stk} kB
VmExe:\t24 kB
VmLib:\t{vm_lib} kB
VmPTE:\t{vm_pte} kB
VmPMD:\t12 kB
VmSwap:\t0 kB
Threads:\t{threads}
SigQ:\t0/11500
SigPnd:\t0000000000000000
ShdPnd:\t0000000000000000
SigBlk:\t0000000000001204
SigIgn:\t0000000000000000
SigCgt:\t00000002000094f8
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
NoNewPrivs:\t0
Seccomp:\t2
Speculation_Store_Bypass:\tunknown
Cpus_allowed:\t{cpus_mask}
Cpus_allowed_list:\t0-{cpus_max}
Mems_allowed:\t1
Mems_allowed_list:\t0
voluntary_ctxt_switches:\t{vol_switches}
nonvoluntary_ctxt_switches:\t{nonvol_switches}
"""

OVERRIDE_URANDOM = False
OVERRIDE_URANDOM_INT = 1

IS_DIR = object()

class ContentGenerator:
    def __init__(self, emulator: 'Emulator'):
        self.__emu: 'Emulator' = emulator
        
        self.cfg = emulator.config
        self.pcb = emulator.pcb
        self.memory_map = emulator.memory
        
        self._sim_vol_switches = random.randint(100, 1000)
        self._sim_nonvol_switches = random.randint(10, 100)

        self.routes: Dict[str, Callable] = {
            r'^/proc$': self._gen_dir,
            r'^/proc/(self|\d+)$': self._gen_dir,
            r'^/proc/(self|\d+)/fd$': self._gen_dir,
            r'^/proc/(self|\d+)/status$': self._gen_status,
            r'^/proc/(self|\d+)/exe$': self._gen_exe,
            r'^/proc/(self|\d+)/maps$': self._gen_maps,
            r'^/proc/(self|\d+)/cmdline$': self._gen_cmdline,
            r'^/proc/(self|\d+)/cgroup$': self._gen_cgroup,
            r'^/sys/devices/system/cpu/online$': self._gen_cpu_online,
            r'^/dev/u?random$': self._dev_urandom,
            r'^/dev/(null|binder)$': self._dev_virtual,
        }

    def prepare_path(self, virt_path: str, host_path: str, ignore_handler: bool = False, **kwargs) -> Tuple[bool, Any]:
        """
        Returns bool if it's virutal directory and its content
        If it's not virtual directory, returns False and path to file
        """
        handler = None

        def find_pattern():
            for pattern, h in self.routes.items():
                if re.match(pattern, virt_path):
                    return h

        if ignore_handler:
            founded = find_pattern()
            if founded:
                return True, None
            else:
                return False, None
            
        handler = find_pattern()

        if not handler:
            if os.path.exists(host_path):
                return os.path.isdir(host_path), host_path
            return False, None

        content = handler(virt_path=virt_path, **kwargs)
        
        return True, content

    # removed writing virtual files to disk

    # def prepare_path(self, virt_path: str, host_path: str, **kwargs) -> Tuple[bool, Optional[str]]:
    #     handler = None
    #     for pattern, h in self.routes.items():
    #         if re.match(pattern, virt_path):
    #             handler = h
    #             break

    #     if not handler:
    #         if os.path.exists(host_path):
    #             return os.path.isdir(host_path), host_path
    #         return False, None

    #     content = handler(virt_path=virt_path, **kwargs)

    #     if isinstance(content, list):
    #         if not os.path.exists(host_path):
    #             os.makedirs(host_path, exist_ok=True)
            
    #         for fake_file in content:
    #             fake_host_file = os.path.join(host_path, fake_file)
    #             if not os.path.exists(fake_host_file):
    #                 open(fake_host_file, 'a').close()
            
    #         return True, host_path

    #     if content is None:
    #         return False, virt_path

    #     return False, self._smart_write(host_path, content, virt_path)

    # def _smart_write(self, host_path: str, content: Any, virt_path: str) -> str:
    #     parent = os.path.dirname(host_path)
    #     if not os.path.exists(parent):
    #         os.makedirs(parent, exist_ok=True)

    #     mode = "wb" if isinstance(content, bytes) else "w"
    #     encoded_content = content if isinstance(content, bytes) else content.encode()

    #     if os.path.exists(host_path):
    #         with open(host_path, "rb") as f:
    #             if f.read() == encoded_content:
    #                 if not any(x in virt_path for x in ["maps", "status"]):
    #                     return host_path

    #     with open(host_path, mode) as f:
    #         f.write(content)
        
    #     return host_path

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
            flags = f"{r}{w}{x}{p}"
            
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

            line = f"{start:08x}-{end:08x} {flags} 00000000 00:00 0"
            
            if path:
                line = line.ljust(73) + path
                
            buf.write(line + "\n")
        return buf.getvalue()

    def _gen_cmdline(self, **kwargs):
        return f"{self.cfg.pkg.pkg_name}\x00"

    def _gen_cpu_online(self, **kwargs):
        return "0-7\n"

    def _gen_cgroup(self, **kwargs):
        return "2:cpu:/\n1:cpuacct:/\n"

    def _dev_urandom(self, count, **kwargs):
        return os.urandom(count)

    def _dev_virtual(self, **kwargs):
        return None