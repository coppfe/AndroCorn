import posixpath
import os.path
import unittest

from androidemu.emulator import Emulator
from androidemu.utils import memory_helpers
from androidemu.const import emu_const

from unicorn import *

class TestGetSign(unittest.TestCase):

    def __init__(self, methodName):
        unittest.TestCase.__init__(self, methodName)

        self.emulator: Emulator = None


    def getprop_arm32(self, prop_name):
        emulator = self.emulator
        vfs_path = emulator.get_vfs_root()

        libcm = emulator.load_library("%s/system/lib/libc.so" % vfs_path, do_init=True, main_lib=True)

        # name_ptr = emulator.memory.map(0, 128, UC_PROT_READ | UC_PROT_WRITE)
        # val_ptr = emulator.memory.map(0, 128, UC_PROT_READ | UC_PROT_WRITE)

        name_ptr = emulator.call_symbol(libcm, 'malloc', 128)
        val_ptr = emulator.call_symbol(libcm, 'malloc', 128)

        try:
            emulator.mu.mem_write(name_ptr, (prop_name + '\0').encode())
            
            emulator.call_symbol(libcm, '__system_property_get', name_ptr, val_ptr)

            result_bytes = memory_helpers.read_utf8(emulator.mu, val_ptr)
            return result_bytes
        
        finally:
            pass

    def getprop_arm64(self, prop_name):
        emulator = self.emulator
        vfs_path = emulator.get_vfs_root()

        libcm = emulator.load_library("%s/system/lib64/libc.so" % vfs_path, do_init=True, main_lib=True)

        # name_ptr = emulator.memory.map(0, 128, UC_PROT_READ | UC_PROT_WRITE)
        # val_ptr = emulator.memory.map(0, 128, UC_PROT_READ | UC_PROT_WRITE)

        name_ptr = emulator.call_symbol(libcm, 'malloc', 128)
        val_ptr = emulator.call_symbol(libcm, 'malloc', 128)

        try:
            emulator.mu.mem_write(name_ptr, (prop_name + '\0').encode())
            
            emulator.call_symbol(libcm, '__system_property_get', name_ptr, val_ptr)

            result_bytes = memory_helpers.read_utf8(emulator.mu, val_ptr)
            return result_bytes
        
        finally:
            pass

    def test_getprop(self):
        test_prop_name = "ro.build.version.release"
        
        self.emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32, muti_task=True)
        result = self.getprop_arm32(test_prop_name)
        
        self.assertIsInstance(result, str, "Result must be a string")
        self.assertTrue(len(result) > 0, "Result must not be empty")
        print(f"[*] Result arm32 '{test_prop_name}': {result}\n\n")

        del self.emulator

        self.emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM64, muti_task=True)
        result = self.getprop_arm64(test_prop_name)
        
        self.assertIsInstance(result, str, "Result must be a string")
        self.assertTrue(len(result) > 0, "Result must not be empty")
        print(f"[*] Result arm64 '{test_prop_name}': {result}")

        del self.emulator


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    unittest.main()

# INFO:root:process pid:16268
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib/libc.so (do_init=True) (main=True)
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
# INFO:root:16268 futex_wake unblock nobody waiting in futex ptr 0x40087018
# [*] Result arm32 'ro.build.version.release': 7.1.2


# INFO:root:process pid:16268
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib64/libc.so (do_init=True) (main=True)
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
# INFO:root:16268 futex_wake unblock nobody waiting in futex ptr 0x400C0030
# [*] Result arm64 'ro.build.version.release': 7.1.2
# .
# ----------------------------------------------------------------------
# Ran 1 test in 0.130s

# OK