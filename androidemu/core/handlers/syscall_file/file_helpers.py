from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc
    from os import stat_result

FIRMWARE_BUILD_TIME = 1678884069 

def _calc_blocks(file_size):
    if file_size == 0:
        return 0
    return ((file_size + 4095) // 4096) * 8

def stat_to_memory2(uc: 'Uc', buf_ptr: int, stat: 'stat_result', uid: int, st_mode: int):
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
    
    sec = FIRMWARE_BUILD_TIME
    nsec = 0

    
    uc.mem_write(buf_ptr + 0,  int(st_dev).to_bytes(8, 'little'))      # 0: st_dev (unsigned long long)
    uc.mem_write(buf_ptr + 8,  int(0).to_bytes(4, 'little'))           # 8: __pad0
    uc.mem_write(buf_ptr + 12, int(st_ino).to_bytes(4, 'little'))      # 12: __st_ino (unsigned long)
    uc.mem_write(buf_ptr + 16, int(st_mode).to_bytes(4, 'little'))     # 16: st_mode
    uc.mem_write(buf_ptr + 20, int(1).to_bytes(4, 'little'))           # 20: st_nlink
    uc.mem_write(buf_ptr + 24, int(uid).to_bytes(4, 'little'))         # 24: st_uid
    uc.mem_write(buf_ptr + 28, int(uid).to_bytes(4, 'little'))         # 28: st_gid
    uc.mem_write(buf_ptr + 32, int(st_rdev).to_bytes(8, 'little'))     # 32: st_rdev (unsigned long long)
    
    # 40-47: Padding
    uc.mem_write(buf_ptr + 40, int(0).to_bytes(4, 'little'))           # 40: __pad3
    # Bytes 44-47: Implicit padding for alignment of st_size (skipped/zeroed)
    uc.mem_write(buf_ptr + 44, int(0).to_bytes(4, 'little'))           
    
    # 48-55: Size
    uc.mem_write(buf_ptr + 48, int(st_size).to_bytes(8, 'little'))     # 48: st_size (long long)
    
    # 56-63: Block info
    uc.mem_write(buf_ptr + 56, int(st_blksize).to_bytes(4, 'little'))  # 56: st_blksize
    # Bytes 60-63: Implicit padding for alignment of st_blocks
    uc.mem_write(buf_ptr + 60, int(0).to_bytes(4, 'little'))
    
    # 64-71: Blocks
    uc.mem_write(buf_ptr + 64, int(st_blocks).to_bytes(8, 'little'))   # 64: st_blocks (long long)
    
    # 72-95: Timestamps (ARM32 uses 32-bit sec + 32-bit nsec)
    uc.mem_write(buf_ptr + 72, int(sec).to_bytes(4, 'little'))         # 72: st_atime
    uc.mem_write(buf_ptr + 76, int(nsec).to_bytes(4, 'little'))        # 76: st_atime_nsec
    uc.mem_write(buf_ptr + 80, int(sec).to_bytes(4, 'little'))         # 80: st_mtime
    uc.mem_write(buf_ptr + 84, int(nsec).to_bytes(4, 'little'))        # 84: st_mtime_nsec
    uc.mem_write(buf_ptr + 88, int(sec).to_bytes(4, 'little'))         # 88: st_ctime
    uc.mem_write(buf_ptr + 92, int(nsec).to_bytes(4, 'little'))        # 92: st_ctime_nsec
    
    # 96-103: 64-bit Inode
    uc.mem_write(buf_ptr + 96, int(st_ino).to_bytes(8, 'little'))      # 96: st_ino (unsigned long long)


def stat_to_memory64(uc: 'Uc', buf_ptr: int, stat: 'stat_result', uid: int, st_mode: int):
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
    
    sec = FIRMWARE_BUILD_TIME
    nsec = 0
        
    uc.mem_write(buf_ptr + 0,  int(st_dev).to_bytes(8, 'little'))      # 0: st_dev
    uc.mem_write(buf_ptr + 8,  int(st_ino).to_bytes(8, 'little'))      # 8: st_ino
    uc.mem_write(buf_ptr + 16, int(st_mode).to_bytes(4, 'little'))     # 16: st_mode
    uc.mem_write(buf_ptr + 20, int(1).to_bytes(4, 'little'))           # 20: st_nlink
    uc.mem_write(buf_ptr + 24, int(uid).to_bytes(4, 'little'))         # 24: st_uid
    uc.mem_write(buf_ptr + 28, int(uid).to_bytes(4, 'little'))         # 28: st_gid
    uc.mem_write(buf_ptr + 32, int(st_rdev).to_bytes(8, 'little'))     # 32: st_rdev
    uc.mem_write(buf_ptr + 40, int(0).to_bytes(8, 'little'))           # 40: __pad1
    
    uc.mem_write(buf_ptr + 48, int(st_size).to_bytes(8, 'little'))     # 48: st_size
    uc.mem_write(buf_ptr + 56, int(st_blksize).to_bytes(4, 'little'))  # 56: st_blksize
    uc.mem_write(buf_ptr + 60, int(0).to_bytes(4, 'little'))           # 60: __pad2
    uc.mem_write(buf_ptr + 64, int(st_blocks).to_bytes(8, 'little'))   # 64: st_blocks
    
    # Timestamps (ARM64 uses 64-bit sec + 64-bit nsec)
    uc.mem_write(buf_ptr + 72, int(sec).to_bytes(8, 'little'))         # 72: st_atime
    uc.mem_write(buf_ptr + 80, int(nsec).to_bytes(8, 'little'))        # 80: st_atime_nsec
    uc.mem_write(buf_ptr + 88, int(sec).to_bytes(8, 'little'))         # 88: st_mtime
    uc.mem_write(buf_ptr + 96, int(nsec).to_bytes(8, 'little'))        # 96: st_mtime_nsec
    uc.mem_write(buf_ptr + 104, int(sec).to_bytes(8, 'little'))        # 104: st_ctime
    uc.mem_write(buf_ptr + 112, int(nsec).to_bytes(8, 'little'))       # 112: st_ctime_nsec
    
    uc.mem_write(buf_ptr + 120, int(0).to_bytes(8, 'little'))          # 120: unused