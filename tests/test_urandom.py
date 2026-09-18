import posixpath
import os.path
import unittest
import time

from androidemu.core.emulator import Emulator
from androidemu.const import emu_const
from unicorn import *
from unicorn.arm64_const import *


class TestMatrixVFS(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.vfs_root = "vfs"
        cls.emulator = Emulator(vfs_root=cls.vfs_root, arch=emu_const.ARCH_ARM64)
        
        cls.libc = cls.emulator.get_library("libc.so")
        assert cls.libc is not None, "libc.so must be loaded by default"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'emulator'):
            del cls.emulator

    def test_getrandom_syscall(self):
        print("\n[*] Testing getrandom entropy (Direct Syscall)...")
        emu = self.emulator
        
        buf_size = 16
        buf_addr = emu.memory.map(0, buf_size, UC_PROT_READ | UC_PROT_WRITE)

        emu.mu.reg_write(UC_ARM64_REG_X0, buf_addr)
        emu.mu.reg_write(UC_ARM64_REG_X1, buf_size)
        emu.mu.reg_write(UC_ARM64_REG_X2, 0)
        emu.mu.reg_write(UC_ARM64_REG_X8, 278)  # getrandom syscall on aarch64

        code_addr = emu.memory.map(0, 4096, UC_PROT_READ | UC_PROT_EXEC)
        emu.mu.mem_write(code_addr, b"\x01\x00\x00\xd4")  # SVC #0 in ARM64
        
        emu.mu.emu_start(code_addr, code_addr + 4, count=1)

        data1 = emu.mu.mem_read(buf_addr, buf_size)
        print(f"    RND result: {data1.hex()}")

        self.assertNotEqual(data1, b"\x00" * buf_size, "Entropy failure: returned zeros!")
        self.assertNotEqual(data1, b"\x01" * buf_size, "Entropy failure: static values!")

    def test_urandom_device(self):
        print("\n[*] Testing /dev/urandom VFD...")
        emu = self.emulator
        libcm = self.libc

        path_ptr = emu.call_symbol(libcm, 'malloc', 64)
        emu.mu.mem_write(path_ptr, b"/dev/urandom\0")
        
        # open("/dev/urandom", O_RDONLY=0)
        fd = emu.call_symbol(libcm, 'open', path_ptr, 0)
        print(f"    Virtual FD: {fd}")
        self.assertGreater(fd, 2, "FD error: expected valid descriptor > 2")

        read_size = 8
        read_buf = emu.call_symbol(libcm, 'malloc', read_size)
        res = emu.call_symbol(libcm, 'read', fd, read_buf, read_size)
        
        data = emu.mu.mem_read(read_buf, read_size)
        print(f"    Read result: {res} bytes, data: {data.hex()}")
        
        self.assertEqual(res, read_size)
        self.assertNotEqual(data, b"\x00" * read_size)

        stat_buf = emu.call_symbol(libcm, 'malloc', 256)
        res_stat = emu.call_symbol(libcm, 'fstat', fd, stat_buf)
        self.assertEqual(res_stat, 0, "fstat on virtual FD failed")
        
        st_mode = int.from_bytes(emu.mu.mem_read(stat_buf + 16, 4), 'little')
        print(f"    Virtual Device Mode: {oct(st_mode)}")
        self.assertTrue(st_mode & 0o20000, "Stat failure: /dev/urandom must be S_IFCHR")

        emu.call_symbol(libcm, 'close', fd)

    def test_virtual_time_warp(self):
        print("\n[*] Testing Virtual Time Warp...")
        emu = self.emulator
        libcm = self.libc

        req_ptr = emu.call_symbol(libcm, 'malloc', 16)
        emu.mu.mem_write(req_ptr, int(2).to_bytes(8, 'little'))  # 2 seconds
        emu.mu.mem_write(req_ptr + 8, int(0).to_bytes(8, 'little'))  # 0 nsec

        time_before_host = time.time()
        time_before_virt = emu.time_manager.get_current_time_us()

        print(f"    Host time before: {time_before_host:.4f}")
        
        emu.call_symbol(libcm, 'nanosleep', req_ptr, 0)

        time_after_host = time.time()
        time_after_virt = emu.time_manager.get_current_time_us()
        
        host_elapsed = time_after_host - time_before_host
        virt_elapsed_sec = (time_after_virt - time_before_virt) / 1000000.0

        print(f"    Host time after:  {time_after_host:.4f} (Elapsed: {host_elapsed:.4f}s)")
        print(f"    Virt time elapsed: {virt_elapsed_sec:.4f}s")

        self.assertLess(host_elapsed, 0.5, "Time Warp Failure: Host actually slept!")
        self.assertGreaterEqual(virt_elapsed_sec, 2.0, "Virtual Time Failure: Time didn't advance!")

    def test_stat_path_consistency(self):
        print("\n[*] Testing Stat Path Consistency...")
        emu = self.emulator
        libcm = self.libc
        
        stat_buf = emu.call_symbol(libcm, 'malloc', 256)
        path_ptr = emu.call_symbol(libcm, 'malloc', 128)

        libc_path = "/system/lib64/libc.so"
        emu.mu.mem_write(path_ptr, libc_path.encode() + b"\0")
        res1 = emu.call_symbol(libcm, 'stat', path_ptr, stat_buf)
        self.assertEqual(res1, 0, "stat on real libc.so failed")
        
        size_real = int.from_bytes(emu.mu.mem_read(stat_buf + 48, 8), 'little')
        print(f"    Real file ({libc_path}) size: {size_real} bytes")
        self.assertGreater(size_real, 0)

        emu.mu.mem_write(path_ptr, b"/dev/urandom\0")
        res2 = emu.call_symbol(libcm, 'stat', path_ptr, stat_buf)
        self.assertEqual(res2, 0, "stat on virtual /dev/urandom failed")
        
        size_virt = int.from_bytes(emu.mu.mem_read(stat_buf + 48, 8), 'little')
        print(f"    Virtual device size: {size_virt} bytes")
        self.assertEqual(size_virt, 0)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)
    unittest.main()