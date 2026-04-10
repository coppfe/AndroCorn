from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ......state.time_manager import TimeManager

class VirtualDeviceStat:
    def __init__(self, fd, dev_name, time_manager: 'TimeManager'):
        self.st_mode = 0o20666  # S_IFCHR | 0666
        self.st_ino = fd
        self.st_dev = (0 << 8) | 6
        self.st_rdev = (1 << 8) | 9 if "random" in dev_name else (1 << 8) | 3
        self.st_nlink = 1
        self.st_size = 0
        v_sec, _ = time_manager.get_timeofday()
        self.st_atime = v_sec
        self.st_mtime = v_sec
        self.st_ctime = v_sec