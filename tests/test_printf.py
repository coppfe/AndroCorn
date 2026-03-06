import unittest
from androidemu.emulator import Emulator
from androidemu.const import emu_const

class TestLibcPrintfCall(unittest.TestCase):

    def setUp(self):
        self.emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32, muti_task=True)

    def tearDown(self):
        del self.emulator

    def test_printf_with_int_and_string(self):
        emulator = self.emulator
        vfs_path = emulator.vfs_root

        libc = emulator.load_library(f"{vfs_path}/system/lib/libc.so", do_init=True)

        fmt_str = b"Hello %s, your number is %d\n\x00"
        fmt_ptr = emulator.call_symbol(libc, "malloc", len(fmt_str))
        emulator.mu.mem_write(fmt_ptr, fmt_str)

        name_str = b"AndroCorn\x00" 
        name_ptr = emulator.call_symbol(libc, "malloc", len(name_str))
        emulator.mu.mem_write(name_ptr, name_str)

        number = 2026

        print("[*] Calling printf via emulator...")
        
        res = emulator.call_symbol(libc, "printf", fmt_ptr, name_ptr, number)
        print(f"[*] printf returned: {res} bytes written")

        try:
            print("[*] Forcing fflush(0)...")
            emulator.call_symbol(libc, "fflush", 0)
        except Exception as e:
            print(f"[*] fflush not needed or failed: {e}")

        emulator.call_symbol(libc, "free", fmt_ptr)
        emulator.call_symbol(libc, "free", name_ptr)

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()