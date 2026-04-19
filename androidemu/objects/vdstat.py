from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..kernel.state.time_manager import TimeManager

class VirtualDeviceStat:
    def __init__(self, 
                 st_mode: int, 
                 st_size: int = 0, 
                 st_ino: int = 0, 
                 st_dev: int = 2051, 
                 st_rdev: int = 0, 
                 st_uid: int = 0, 
                 st_gid: int = 0, 
                 st_nlink: int = 1,
                 st_blksize: int = 4096,
                 st_blocks: Optional[int] = None,
                 time_manager: 'TimeManager' = None,
                 atime_us: Optional[int] = None,
                 mtime_us: Optional[int] = None,
                 ctime_us: Optional[int] = None):
        
        self.st_mode = st_mode
        self.st_size = st_size
        self.st_ino = st_ino
        self.st_dev = st_dev
        self.st_rdev = st_rdev
        self.st_uid = st_uid
        self.st_gid = st_gid
        self.st_nlink = st_nlink
        self.st_blksize = st_blksize
        self.st_blocks = st_blocks if st_blocks is not None else (st_size + 511) // 512

        if time_manager:
            curr_virtual_us = time_manager.get_current_time_us()
        else:
            curr_virtual_us = 0

        a_us = atime_us if atime_us is not None else curr_virtual_us
        m_us = mtime_us if mtime_us is not None else curr_virtual_us
        c_us = ctime_us if ctime_us is not None else curr_virtual_us

        self.st_atime = a_us // 1_000_000
        self.st_mtime = m_us // 1_000_000
        self.st_ctime = c_us // 1_000_000

        self.st_atime_nsec = (a_us % 1_000_000) * 1000
        self.st_mtime_nsec = (m_us % 1_000_000) * 1000
        self.st_ctime_nsec = (c_us % 1_000_000) * 1000

    @classmethod
    def create_regular_file(cls, size: int, time_manager: 'TimeManager', uid: int = 0, gid: int = 0, permissions: int = 0o644, **kwargs):
        return cls(
            st_mode=(0o100000 | permissions),
            st_size=size,
            st_uid=uid,
            st_gid=gid,
            time_manager=time_manager,
            **kwargs
        )

    @classmethod
    def create_directory(cls, time_manager: 'TimeManager', uid: int = 0, gid: int = 0, permissions: int = 0o755, **kwargs):
        return cls(
            st_mode=(0o040000 | permissions),
            st_size=4096,
            st_uid=uid,
            st_gid=gid,
            st_nlink=2,
            time_manager=time_manager,
            **kwargs
        )

    @classmethod
    def create_char_device(cls, major: int, minor: int, time_manager: 'TimeManager', uid: int = 0, gid: int = 0, permissions: int = 0o666, **kwargs):
        return cls(
            st_mode=(0o020000 | permissions),
            st_size=0,
            st_uid=uid,
            st_gid=gid,
            st_rdev=(major << 8) | minor,
            time_manager=time_manager,
            **kwargs
        )