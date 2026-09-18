from typing import TYPE_CHECKING
import struct

if TYPE_CHECKING:
    from unicorn import Uc
    from ...kernel.fs.vdstat import VirtualDeviceStat

# def _calc_blocks(file_size):
#     if file_size == 0:
#         return 0
#     return ((file_size + 4095) // 4096) * 8

def stat_to_memory2(uc: 'Uc', buf_ptr: int, stat: 'VirtualDeviceStat'):
    '''
    ARM32 (ARMv7a / EABI) struct stat64 Layout
    Total Size: строго 104 байта
    '''
    data = struct.pack(
        "<Q IIIIII Q I 4x Q I 4x Q II II II Q",
        stat.st_dev,
        0, stat.st_ino, stat.st_mode, stat.st_nlink, stat.st_uid, stat.st_gid,
        stat.st_rdev,
        0,                 # __pad3 (4)
        # 4x
        stat.st_size,
        stat.st_blksize,
        # 4x
        stat.st_blocks,
        stat.st_atime, stat.st_atime_nsec,
        stat.st_mtime, stat.st_mtime_nsec,
        stat.st_ctime, stat.st_ctime_nsec,
        stat.st_ino
    )
    assert len(data) == 104, f"Invalid ARM32 stat64 size: {len(data)} (expected 104)"
    uc.mem_write(buf_ptr, data)

def stat_to_memory64(uc: 'Uc', buf_ptr: int, stat: 'VirtualDeviceStat'):
    '''
    ARM64 (AArch64 struct stat) Layout
    Total Size: 128 bytes
    '''

    data = struct.pack(
        "< QQ IIII QQ Q II Q QQQQQQ Q",
        stat.st_dev, stat.st_ino,
        stat.st_mode, stat.st_nlink, stat.st_uid, stat.st_gid,
        stat.st_rdev, 0,
        stat.st_size,
        stat.st_blksize, 0,
        stat.st_blocks,
        stat.st_atime, stat.st_atime_nsec,
        stat.st_mtime, stat.st_mtime_nsec,
        stat.st_ctime, stat.st_ctime_nsec,
        0
    )
    uc.mem_write(buf_ptr, data)