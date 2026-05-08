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