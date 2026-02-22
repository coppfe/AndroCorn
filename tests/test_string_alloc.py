import unittest
import struct
from androidemu.emulator import Emulator
from androidemu.const import emu_const

class TestLibCppSharedCall(unittest.TestCase):

    def setUp(self):
        self.emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32, muti_task=True)

    def tearDown(self):
        del self.emulator

    def test_cpp_string_constructor_with_data(self):
        emulator = self.emulator
        vfs_path = emulator.get_vfs_root()

        libc = emulator.load_library(f"{vfs_path}/system/lib/libc.so", do_init=True)
        libcpp = emulator.load_library(f"{vfs_path}/system/lib/libc++_shared.so", do_init=True)

        symbol_name = "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2IPcvEET_S8_"

        test_str = b"AndroidCorn2026"
        str_input_ptr = emulator.call_symbol(libc, "malloc", len(test_str) + 1)
        emulator.mu.mem_write(str_input_ptr, test_str + b"\x00")
        
        obj_ptr = emulator.call_symbol(libc, "malloc", 32)

        print(f"[*] Calling C++ constructor with short string...")
        res_ptr = emulator.call_symbol(libcpp, symbol_name, obj_ptr, str_input_ptr, str_input_ptr + len(test_str))
        
        obj_mem = emulator.mu.mem_read(res_ptr, 12)
        size_raw, cap_raw, ptr_or_data = struct.unpack("<III", obj_mem)

        if (size_raw & 1) == 0:
            print("[*] SSO detected (Short String Optimization)")
            actual_data_ptr = res_ptr + 1
            real_size = size_raw >> 1
        else:
            print("[*] Heap detected (Long String)")
            actual_data_ptr = ptr_or_data
            real_size = size_raw

        print(f"[*] Calculated data pointer: {hex(actual_data_ptr)}")

        result_bytes = emulator.mu.mem_read(actual_data_ptr, len(test_str))
        result_text = result_bytes.decode('utf-8')
        
        print(f"[*] Success! Read: {result_text}")
        self.assertEqual(result_text, test_str.decode())
        
        emulator.call_symbol(libc, "free", str_input_ptr)
        emulator.call_symbol(libc, "free", obj_ptr)

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    unittest.main()

# INFO:root:process pid:11904
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm32.tls_bootstrap:[TLS-7.1-ARM32] Bootstrapping Legacy Layout
# INFO:androidemu.internal.bionic.arm32.tls_bootstrap:TLS 7.1 Ready. TP: 0x2000000, DTV: 0x2005000, Pthread: 0x2005610
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# INFO:root:open [vfs//dev/__properties__][0xa8000] return fd 3
# INFO:root:open [vfs//sys/devices/system/cpu/online][0xa0000] return fd 3
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40087018
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib/libc++_shared.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:  [Init] libc++_shared.so
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129654
# INFO:root:11904 futex_wake unblock nobody waiting in futex ptr 0x40129900
# [*] Calling C++ constructor with short string...
# [*] Heap detected (Long String)
# [*] Calculated data pointer: 0x70a0d020
# [*] Success! Read: AndroCorn2026
# .
# ----------------------------------------------------------------------
# Ran 1 test in 0.140s

# OK