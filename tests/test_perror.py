import unittest
import logging
from androidemu.emulator import Emulator
from androidemu.const import emu_const

class TestBionicPerror(unittest.TestCase):

    def setUp(self):
        self.arch = emu_const.ARCH_ARM32
        self.emulator = Emulator(vfs_root="vfs", arch=self.arch, muti_task=True)

    def tearDown(self):
        del self.emulator

    def test_perror_reads_errno_directly(self):
        emulator = self.emulator
        vfs_path = emulator.vfs_root
        
        libc_path = f"{vfs_path}/system/lib64/libc.so" if self.arch == emu_const.ARCH_ARM64 else f"{vfs_path}/system/lib/libc.so"
        libc = emulator.load_library(libc_path, do_init=True)

        test_errno = 127
        emulator.tls_utils.set_errno(test_errno)
        
        print(f"[*] Force-set errno to {test_errno}. Now calling perror...")

        prefix_str = b"AndroCorn_Report\x00"
        prefix_ptr = emulator.call_symbol(libc, "malloc", len(prefix_str))
        emulator.mu.mem_write(prefix_ptr, prefix_str)

        print("--- Native perror output start ---")
        emulator.call_symbol(libc, "perror", prefix_ptr)
        print("--- Native perror output end ---")

        emulator.call_symbol(libc, "free", prefix_ptr)

if __name__ == "__main__":
    # logging.basicConfig(level=logging.DEBUG)
    unittest.main()

# ARM64
# [*] Force-set errno to 127. Now calling perror...
# --- Native perror output start ---
# AndroCorn_Report: Key has expired
# --- Native perror output end ---
# .
# ----------------------------------------------------------------------
# Ran 1 test in 0.104s

# OK

# ARM32
# [*] Force-set errno to 127. Now calling perror...
# --- Native perror output start ---
# AndroCorn_Report: Key has expired
# --- Native perror output end ---
# .
# ----------------------------------------------------------------------
# Ran 1 test in 0.105s

# OK
# PS C:\Users\Kirill\Desktop\androidemu> 