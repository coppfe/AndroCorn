STATUS_TEMPLATE = """Name:\t{pkg_name}
Umask:\t0022
State:\tR (running)
Tgid:\t{pid}
Pid:\t{pid}
PPid:\t{ppid}
TracerPid:\t{tracerpid}
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
SigBlk:\t0000000000000000
SigIgn:\t0000000000000000
SigCgt:\t0000000000000000
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

MOUNTINFO = ("14 20 0:11 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw\n"
            "15 20 0:12 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
            "16 20 0:5 / /dev rw,nosuid,relatime - devtmpfs ueventd rw\n"
            "17 14 0:13 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw\n"
            "20 1 259:0 / / rw,relatime - ext4 /dev/block/mmcblk0p42 ro,seclabel\n"
            "21 20 0:15 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,seclabel\n"
            "22 20 0:16 / /dev/cpuctl rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu\n"
            "23 20 0:17 / /dev/cpuset rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpuset\n"
            "25 20 0:18 / /dev/stune rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,stune\n"
            "26 20 0:19 / /mnt rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel\n"
            "27 20 259:1 / /vendor ro,nosuid,nodev,relatime - ext4 /dev/block/mmcblk0p43 ro,seclabel\n"
            "28 20 259:2 / /system ro,relatime - ext4 /dev/block/mmcblk0p44 ro,seclabel\n"
            "29 20 259:3 / /data rw,nosuid,nodev,noatime - ext4 /dev/block/mmcblk0p45 rw,seclabel\n")