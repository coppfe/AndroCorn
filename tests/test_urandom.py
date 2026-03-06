import posixpath
import os.path
import unittest
import time

from androidemu.emulator import Emulator
from androidemu.utils.memory import memory_helpers
from androidemu.const import emu_const
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

class TestMatrixVFS(unittest.TestCase):

    def setUp(self):
        self.vfs_root = "vfs"
        self.emulator = Emulator(vfs_root=self.vfs_root, arch=emu_const.ARCH_ARM64, muti_task=True)

    def tearDown(self):
        if self.emulator:
            del self.emulator

    def test_getrandom_syscall(self):
        print("\n[*] Testing getrandom entropy (Direct Syscall)...")
        emu = self.emulator
        
        buf_size = 16
        buf_addr = emu.memory.map(0, buf_size, UC_PROT_READ | UC_PROT_WRITE)

        emu.mu.reg_write(UC_ARM64_REG_X0, buf_addr)
        emu.mu.reg_write(UC_ARM64_REG_X1, buf_size)
        emu.mu.reg_write(UC_ARM64_REG_X2, 0)
        emu.mu.reg_write(UC_ARM64_REG_X8, 278)

        code_addr = emu.memory.map(0, 4096, UC_PROT_READ | UC_PROT_EXEC)
        emu.mu.mem_write(code_addr, b"\x01\x00\x00\xd4") # SVC #0 in ARM64
        
        emu.mu.emu_start(code_addr, code_addr + 4, count=1)

        data1 = emu.mu.mem_read(buf_addr, buf_size)
        print(f"    RND result: {data1.hex()}")

        self.assertNotEqual(data1, b"\x00" * buf_size, "Entropy failure: returned zeros!")
        self.assertNotEqual(data1, b"\x01" * buf_size, "Entropy failure: static values!")

    def test_urandom_device(self):
        print("\n[*] Testing /dev/urandom VFD...")
        emu = self.emulator
        libcm = emu.load_library(f"{self.vfs_root}/system/lib64/libc.so", do_init=True)

        path_ptr = emu.call_symbol(libcm, 'malloc', 64)
        emu.mu.mem_write(path_ptr, b"/dev/urandom\0")
        
        # open("/dev/urandom", O_RDONLY=0)
        fd = emu.call_symbol(libcm, 'open', path_ptr, 0)
        print(f"    Virtual FD: {fd}")
        self.assertGreaterEqual(fd, 1000, "VFD range error: expected >= 1000 for virtual device")

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
        libcm = emu.load_library(f"{self.vfs_root}/system/lib64/libc.so", do_init=True)

        req_ptr = emu.call_symbol(libcm, 'malloc', 16)
        emu.mu.mem_write(req_ptr, int(2).to_bytes(8, 'little')) # 2 seconds
        emu.mu.mem_write(req_ptr + 8, int(0).to_bytes(8, 'little')) # 0 nsec

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
        libcm = emu.load_library(f"{self.vfs_root}/system/lib64/libc.so", do_init=True)
        
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
    logging.basicConfig(level=logging.INFO)
    unittest.main()

# INFO:root:process pid:14984
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: system/lib64/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrapping Modern Layout
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrap Done. TP=0x2000000, KAB=0x2004ce8, DTV=0x2004000, Pthread=0x2004210
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# INFO:root:open [vfs//dev/__properties__][0x88000] return fd 3
# INFO:root:open [vfs//sys/devices/system/cpu/online][0x80000] return fd 3
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# INFO:androidemu.internal.linker:[Linker] Request to load: libc.so (do_init=False) (main=False) 

# [*] Testing getrandom entropy (Direct Syscall)...
#     RND result: 779314614f5ca6247f38c9a73a3d07cb
# .INFO:root:process pid:14976
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: system/lib64/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrapping Modern Layout
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrap Done. TP=0x2000000, KAB=0x2004ce8, DTV=0x2004000, Pthread=0x2004210
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# INFO:root:open [vfs//dev/__properties__][0x88000] return fd 3
# INFO:root:open [vfs//sys/devices/system/cpu/online][0x80000] return fd 3
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# INFO:androidemu.internal.linker:[Linker] Request to load: libc.so (do_init=False) (main=False)

# [*] Testing Stat Path Consistency...
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib64/libc.so (do_init=True) (main=False)
#     Real file (/system/lib64/libc.so) size: 984664 bytes
#     Virtual device size: 0 bytes
# .INFO:root:process pid:12657
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: system/lib64/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrapping Modern Layout
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrap Done. TP=0x2000000, KAB=0x2004ce8, DTV=0x2004000, Pthread=0x2004210
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# INFO:root:open [vfs//dev/__properties__][0x88000] return fd 3
# INFO:root:open [vfs//sys/devices/system/cpu/online][0x80000] return fd 3
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# INFO:androidemu.internal.linker:[Linker] Request to load: libc.so (do_init=False) (main=False)

# [*] Testing /dev/urandom VFD...
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib64/libc.so (do_init=True) (main=False)
# INFO:root:Opened VIRTUAL device /dev/urandom as fd 1000
#     Virtual FD: 1000
#     Read result: 8 bytes, data: 95f08fbfd99d75d4
#     Virtual Device Mode: 0o20666
# .INFO:root:process pid:13741
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: system/lib64/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrapping Modern Layout
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrap Done. TP=0x2000000, KAB=0x2004ce8, DTV=0x2004000, Pthread=0x2004210
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# INFO:root:open [vfs//dev/__properties__][0x88000] return fd 3
# INFO:root:open [vfs//sys/devices/system/cpu/online][0x80000] return fd 3
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# INFO:androidemu.internal.linker:[Linker] Request to load: libc.so (do_init=False) (main=False)

# [*] Testing Virtual Time Warp...
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib64/libc.so (do_init=True) (main=False)
#     Host time before: 1772828865.6815
#     Host time after:  1772828865.6825 (Elapsed: 0.0010s)
#     Virt time elapsed: 2000.0002s
# .
# ----------------------------------------------------------------------
# Ran 4 tests in 0.263s

# OK