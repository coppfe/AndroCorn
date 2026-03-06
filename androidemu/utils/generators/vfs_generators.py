import os
import logging
import random

from typing import TYPE_CHECKING, Tuple, Optional

if TYPE_CHECKING:
    from ...config import Config
    from ...pcb import Pcb
    from ..memory.memory_map import MemoryMap

STATUS_TEMPLATE = """Name:\t{pkg_name}
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

class VFSGenerator:
    def __init__(self, cfg: 'Config', pcb: 'Pcb', memory_map: 'MemoryMap'):
        self.cfg: 'Config' = cfg
        self.pcb: 'Pcb' = pcb
        self.memory_map: 'MemoryMap' = memory_map
        
        self._sim_vol_switches = random.randint(100, 1000)
        self._sim_nonvol_switches = random.randint(10, 100)
        
        self.generators = {
            "/proc/self/cmdline": self._gen_cmdline,
            "/proc/self/status": self._gen_status,
            "/proc/self/cgroup": self._gen_cgroup,
            "/proc/self/maps": self._gen_maps,
            "/sys/devices/system/cpu/online": self._gen_cpu_online,
            
            # Virtual Devices
            "/dev/urandom": self._dev_virtual,
            "/dev/random": self._dev_virtual,
            "/dev/null": self._dev_virtual,
        }

    def prepare_path(self, virt_path: str, host_path: str, **kwargs) -> Tuple[bool, Optional[str]]:
        pid_str = str(self.pcb.get_pid())
        norm_path = virt_path.replace(f"/proc/{pid_str}/", "/proc/self/")

        if norm_path not in self.generators:
            if os.path.exists(host_path):
                return False, host_path
            return False, None

        handler = self.generators[norm_path]

        try:
            content = handler(**kwargs)
        except Exception as e:
            logging.error(f"[VFS] Error generating {norm_path}: {e}")
            return False, None

        if content is None:
            return True, norm_path

        is_dynamic = norm_path in ["/proc/self/maps", "/proc/self/status"]
        
        if is_dynamic or not os.path.exists(host_path):
            parent = os.path.dirname(host_path)
            if not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

            mode = "wb" if isinstance(content, bytes) else "w"
            with open(host_path, mode) as f:
                f.write(content)

        return False, host_path

    def _gen_status(self, **kwargs):
        self._sim_vol_switches += random.randint(1, 5)
        self._sim_nonvol_switches += random.randint(0, 1)

        vm_size_kb = random.randint(100000, 200000) 

        return STATUS_TEMPLATE.format(
            pkg_name=self.cfg.get("pkg_name"),
            pid=self.pcb.pid,
            ppid=self.cfg.get("ppid", 821),
            uid=self.pcb.uid,
            vm_peak=vm_size_kb + 1024,
            vm_size=vm_size_kb,
            vm_hwm=vm_size_kb,
            vm_rss=vm_size_kb // 2,
            vm_data=vm_size_kb // 3,
            vm_stk=8192,
            vm_lib=32000,
            vm_pte=512,
            threads=self.pcb.threads,
            cpus_mask="ff",
            cpus_max=7,
            vol_switches=self._sim_vol_switches,
            nonvol_switches=self._sim_nonvol_switches
        )

    def _gen_cmdline(self, **kwargs):
        return f"{self.cfg.get('pkg_name')}\x00"

    def _gen_maps(self, **kwargs):
        import io
        buf = io.StringIO()
        self.memory_map.dump_maps(buf)
        return buf.getvalue()
    
    def _gen_cpu_online(self, **kwargs):
        return "0-7\n"
    
    def _gen_cgroup(self, **kwargs):
        return f"2:cpu:/\n1:cpuacct:/\n"
    
    def _dev_virtual(self, **kwargs):
        return None 