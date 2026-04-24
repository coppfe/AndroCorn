from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc
    from os import stat_result
    from ...config import Config

class TableWriter:
    def __init__(self, uc: 'Uc', base):
        self.uc: 'Uc' = uc
        self.base = base
        self.offset = 0

    def u64(self, value):
        """
        Write a 64-bit unsigned integer to the table

        :param value: The value to write
        :type value: int
        """
        self.uc.mem_write(self.base + self.offset, int(value).to_bytes(8, 'little'))
        self.offset += 8

    def u32(self, value):
        """
        Write a 32-bit unsigned integer to the table

        :param value: The value to write
        :type value: int
        """
        self.uc.mem_write(self.base + self.offset, int(value).to_bytes(4, 'little'))
        self.offset += 4

def _calc_blocks(file_size):
    if file_size == 0:
        return 0
    return ((file_size + 4095) // 4096) * 8

def stat_to_memory2(uc: 'Uc', buf_ptr: int, stat: 'stat_result', uid: int, st_mode: int, config: 'Config'):
    '''
    ARM32 (struct stat64) Layout
    Total Size: 104 bytes (usually)
    '''
    
    st_dev = (253 << 8) | 0
    st_ino = stat.st_ino & 0xFFFFFFFF if hasattr(stat, "st_ino") else 12345
    st_rdev = stat.st_rdev if hasattr(stat, "st_rdev") else 0
    
    st_size = stat.st_size
    st_blksize = 4096 
    st_blocks = _calc_blocks(st_size)
    
    sec = config.pkg.build_at
    nsec = 0

    w = TableWriter(uc, buf_ptr)
    
    # 0-7: Device
    w.u64(st_dev)      # st_dev (unsigned long long)

    # 8-15: inode (legacy layout)
    w.u32(0)           # __pad0
    w.u32(st_ino)      # __st_ino (unsigned long)

    # 16-31: Basic metadata
    w.u32(st_mode)     # st_mode
    w.u32(1)           # st_nlink
    w.u32(uid)         # st_uid
    w.u32(uid)         # st_gid

    # 32-39: Device type
    w.u64(st_rdev)     # st_rdev (unsigned long long)

    # 40-47: Padding
    w.u32(0)           # __pad3
    w.u32(0)           # alignment padding

    # 48-55: File size
    w.u64(st_size)     # st_size (long long)

    # 56-63: Block info
    w.u32(st_blksize)  # st_blksize
    w.u32(0)           # alignment padding

    # 64-71: Blocks
    w.u64(st_blocks)   # st_blocks (long long)

    # 72-95: Timestamps (ARM32 uses 32-bit sec + 32-bit nsec)
    w.u32(sec)         # st_atime
    w.u32(nsec)        # st_atime_nsec
    w.u32(sec)         # st_mtime
    w.u32(nsec)        # st_mtime_nsec
    w.u32(sec)         # st_ctime
    w.u32(nsec)        # st_ctime_nsec

    # 96-103: 64-bit inode
    w.u64(st_ino)      # st_ino (unsigned long long)


def stat_to_memory64(uc: 'Uc', buf_ptr: int, stat: 'stat_result', uid: int, st_mode: int, config: 'Config'):
    '''
    ARM64 (AArch64 struct stat) Layout
    Total Size: 128 bytes
    '''
    
    st_dev = (253 << 8) | 0  
    st_ino = stat.st_ino if hasattr(stat, 'st_ino') else 12345
    st_rdev = stat.st_rdev if hasattr(stat, "st_rdev") else 0

    st_size = stat.st_size
    st_blksize = 4096
    st_blocks = _calc_blocks(st_size)
    
    sec = config.pkg.build_at
    nsec = 0

    w = TableWriter(uc, buf_ptr)
        
    # 0-15: Device + inode
    w.u64(st_dev)      # st_dev
    w.u64(st_ino)      # st_ino

    # 16-31: Basic metadata
    w.u32(st_mode)     # st_mode
    w.u32(1)           # st_nlink
    w.u32(uid)         # st_uid
    w.u32(uid)         # st_gid

    # 32-47: Device + padding
    w.u64(st_rdev)     # st_rdev
    w.u64(0)           # __pad1

    # 48-63: Size + block info
    w.u64(st_size)     # st_size
    w.u32(st_blksize)  # st_blksize
    w.u32(0)           # __pad2

    # 64-71: Blocks
    w.u64(st_blocks)   # st_blocks

    # 72-119: Timestamps (ARM64: 64-bit sec + 64-bit nsec)
    w.u64(sec)         # st_atime
    w.u64(nsec)        # st_atime_nsec
    w.u64(sec)         # st_mtime
    w.u64(nsec)        # st_mtime_nsec
    w.u64(sec)         # st_ctime
    w.u64(nsec)        # st_ctime_nsec

    # 120-127: unused
    w.u64(0)           # unused