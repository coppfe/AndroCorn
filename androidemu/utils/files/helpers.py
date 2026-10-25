import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..memory.map import MemoryMap
    from ...kernel.fs.vdstat import VirtualDeviceStat


def stat_to_memory2(mem: 'MemoryMap', buf_ptr: int, stat: 'VirtualDeviceStat') -> None:
    """
    ARM32 (ARMv7a / EABI) struct stat64 Layout
    Total Size: 104 bytes
    """
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
    mem.write_bytes(buf_ptr, data)


def stat_to_memory64(mem: 'MemoryMap', buf_ptr: int, stat: 'VirtualDeviceStat') -> None:
    """
    ARM64 (AArch64 struct stat) Layout
    Total Size: 128 bytes
    """
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
    assert len(data) == 128, f"Invalid ARM64 stat size: {len(data)} (expected 128)"
    mem.write_bytes(buf_ptr, data)