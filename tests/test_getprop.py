import posixpath
import os.path
import unittest

from androidemu.emulator import Emulator
from androidemu.utils.memory import memory_helpers
from androidemu.const import emu_const

from unicorn import *

class TestGetSign(unittest.TestCase):

    def __init__(self, methodName):
        unittest.TestCase.__init__(self, methodName)

        self.emulator: Emulator = None


    def getprop_arm32(self, prop_name):
        emulator = self.emulator
        vfs_path = emulator.vfs_root

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
        vfs_path = emulator.vfs_root

        libcm = emulator.load_library("%s/system/lib64/libc.so" % vfs_path, do_init=True, main_lib=True)

        # name_ptr = emulator.memory.map(0, 128, UC_PROT_READ | UC_PROT_WRITE)
        # val_ptr = emulator.memory.map(0, 128, UC_PROT_READ | UC_PROT_WRITE)

        name_ptr = emulator.call_symbol(libcm, 'malloc', 128)
        val_ptr = emulator.call_symbol(libcm, 'malloc', 128)

        try:
            emulator.mu.mem_write(name_ptr, (prop_name + '\0').encode())
            
            emulator.call_symbol(libcm, '__system_property_get', name_ptr, val_ptr)

            result_bytes = memory_helpers.read_utf8(emulator.mu, val_ptr)

            sysconf = emulator.call_symbol(libcm, 'sysconf', 100)
            print(f"[*] sysconf: {sysconf}")

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
    logging.basicConfig(level=logging.DEBUG)
    import cProfile
    import pstats
    import io

    pr = cProfile.Profile()
    pr.enable()

    unittest.main(exit=False)

    pr.disable()

    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats(40)

    print(s.getvalue())

# INFO:root:process pid:4386
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# DEBUG:androidemu.internal.bionic.tls_factory:[*] Creating TLS backend for arch: ARM32
# DEBUG:androidemu.native.symbol_hooks:[+] Symbol hooks initialized
# INFO:androidemu.internal.linker:[Linker] Request to load: system/lib/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# DEBUG:androidemu.internal.linker:  [Load] Parsing libc.so
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0x0 size: 0x802e8
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0x81e00 size: 0xc514
# DEBUG:androidemu.utils.memory.memory_helpers:[+] mem_map success: 0x40000000 - 0x4008f000 (size: 0x8f000)
# DEBUG:androidemu.internal.linker:[*] ELF mapped to 0x40000000. Size: 0x8f000. Bias: 0x40000000. Segments: 2. Min: 0x0, Max: 0x8e314
# DEBUG:androidemu.internal.linker:[*] soinfo: 0x20000000 for vfs//system/lib/libc.so. Next: 0x200000a4. Size: 0xa4.
# DEBUG:androidemu.internal.linker:  [Load] Parsing libdl.so
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0x0 size: 0x1ef8
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0x3edc size: 0x128
# DEBUG:androidemu.utils.memory.memory_helpers:[+] mem_map success: 0x40090000 - 0x40095000 (size: 0x5000)
# DEBUG:androidemu.internal.linker:[*] ELF mapped to 0x40090000. Size: 0x5000. Bias: 0x40090000. Segments: 2. Min: 0x0, Max: 0x4004  
# DEBUG:androidemu.internal.linker:[*] soinfo: 0x200000a4 for vfs//system/lib/libdl.so. Next: 0x20000148. Size: 0xa4.
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm32.tls_bootstrap:[TLS-7.1-ARM32] Bootstrapping Legacy Layout
# DEBUG:androidemu.internal.bionic.arm32.dtv_builder:[DTV-ARM32] Built at 0x2005000
# DEBUG:androidemu.internal.bionic.arm32.pthread_builder:[PThread-7.1-ARM32] Built at 0x2005610. TID: 4387, DTV: 0x2005000 at +0x30  
# INFO:androidemu.internal.bionic.arm32.tls_bootstrap:TLS 7.1 Ready. TP: 0x2000000, DTV: 0x2005000, Pthread: 0x2005610
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# DEBUG:androidemu.internal.linker:  [Reloc] Applying to libc.so
# DEBUG:androidemu.internal.linker:  [Reloc] Relocations: 2125. is_64: 0. Bias: 0x40000000
# DEBUG:androidemu.internal.linker:  [Reloc] Applying to libdl.so
# DEBUG:androidemu.internal.linker:  [Reloc] Relocations: 17. is_64: 0. Bias: 0x40090000
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# DEBUG:root:4386 syscall 125 lr=0x4001ac31
# DEBUG:root:4386 Executing mprotect(0x40088000, 0x1000, 0x1) at 0x40049200 from 0x4001ac31
# DEBUG:root:4386 syscall mprotect returned 0x0
# DEBUG:root:4386 syscall 125 lr=0x4001abb3
# DEBUG:root:4386 Executing mprotect(0x40088000, 0x1000, 0x3) at 0x40049200 from 0x4001abb3
# DEBUG:root:4386 syscall mprotect returned 0x0
# DEBUG:root:4386 syscall 125 lr=0x4001abd5
# DEBUG:root:4386 Executing mprotect(0x40088000, 0x1000, 0x1) at 0x40049200 from 0x4001abd5
# DEBUG:root:4386 syscall mprotect returned 0x0
# DEBUG:root:4386 syscall 327 lr=0x4001f789
# DEBUG:root:4386 Executing fstatat64(0xffffff9c, 0x40085234, 0x107fbf78, 0x0) at 0x40048bf8 from 0x4001f789
# DEBUG:root:4386 syscall fstatat64 returned 0x0
# DEBUG:root:4386 syscall 322 lr=0x4001c93d
# DEBUG:root:4386 Executing openat(0xffffff9c, 0x40085234, 0xa8000, 0x0) at 0x400483d8 from 0x4001c93d
# INFO:root:open [vfs//dev/__properties__][0xa8000] return fd 3
# DEBUG:root:4386 syscall openat returned 0x3
# DEBUG:root:4386 syscall 197 lr=0x4001f587
# DEBUG:root:4386 Executing fstat64(0x3, 0x107fbef8) at 0x40048bd4 from 0x4001f587
# DEBUG:root:4386 syscall fstat64 returned 0x0
# DEBUG:root:4386 syscall 192 lr=0x40020a3d
# DEBUG:root:4386 Executing mmap2(0x0, 0x20000, 0x1, 0x1, 0x3, 0x0) at 0x400483b4 from 0x40020a3d
# DEBUG:root:mmap return 0x70100000
# DEBUG:root:4386 syscall mmap2 returned 0x70100000
# DEBUG:root:4386 syscall 6 lr=0x40019bab
# DEBUG:root:4386 Executing close(0x3) at 0x40048024 from 0x40019bab
# DEBUG:root:4386 syscall close returned 0x0
# DEBUG:root:4386 syscall 45 lr=0x40019835
# DEBUG:root:4386 Executing brk(0x0) at 0x400481c8 from 0x40019835
# DEBUG:androidemu.kernel.syscalls.syscall_memory.memory_syscall_handler: Initialized brk heap at 0x70120000 - 0x70920000
# DEBUG:root:4386 syscall brk returned 0x70120000
# DEBUG:root:4386 syscall 192 lr=0x40020a3d
# DEBUG:root:4386 Executing mmap2(0x0, 0x80000, 0x3, 0x22, 0xffffffff, 0x0) at 0x400483b4 from 0x40020a3d
# DEBUG:root:mmap return 0x70920000
# DEBUG:root:4386 syscall mmap2 returned 0x70920000
# DEBUG:root:4386 syscall 220 lr=0x40020a6d
# DEBUG:root:4386 Executing madvise(0x70920000, 0x80000, 0xc) at 0x400490fc from 0x40020a6d
# DEBUG:root:4386 syscall madvise returned 0x0
# DEBUG:root:4386 syscall 172 lr=0x4006818b
# DEBUG:root:4386 Executing prctl(0x53564d41, 0x0, 0x70920000, 0x80000, 0x40078469) at 0x40049328 from 0x4006818b
# DEBUG:root:prctl: option=0x53564d41 arg2=0 arg3=70920000 arg4=80000 arg5=40078469
# DEBUG:root:4386 syscall 91 lr=0x400681af
# DEBUG:root:4386 Executing munmap(0x70920000, 0x80000) at 0x40049290 from 0x400681af
# DEBUG:root:4386 syscall munmap returned 0x0
# DEBUG:root:4386 syscall 192 lr=0x40020a3d
# DEBUG:root:4386 Executing mmap2(0x0, 0xff000, 0x3, 0x22, 0xffffffff, 0x0) at 0x400483b4 from 0x40020a3d
# DEBUG:root:mmap return 0x70920000
# DEBUG:root:4386 syscall mmap2 returned 0x70920000
# DEBUG:root:4386 syscall 220 lr=0x40020a6d
# DEBUG:root:4386 Executing madvise(0x70920000, 0xff000, 0xc) at 0x400490fc from 0x40020a6d
# DEBUG:root:4386 syscall madvise returned 0x0
# DEBUG:root:4386 syscall 172 lr=0x4006818b
# DEBUG:root:4386 Executing prctl(0x53564d41, 0x0, 0x70920000, 0xff000, 0x40078469) at 0x40049328 from 0x4006818b
# DEBUG:root:prctl: option=0x53564d41 arg2=0 arg3=70920000 arg4=ff000 arg5=40078469
# DEBUG:root:4386 syscall 91 lr=0x400681af
# DEBUG:root:4386 Executing munmap(0x70920000, 0x60000) at 0x40049290 from 0x400681af
# DEBUG:root:4386 syscall munmap returned 0x0
# DEBUG:root:4386 syscall 91 lr=0x400681af
# DEBUG:root:4386 Executing munmap(0x70a00000, 0x1f000) at 0x40049290 from 0x400681af
# DEBUG:root:4386 syscall munmap returned 0x0
# DEBUG:root:4386 syscall 263 lr=0x400680e5
# DEBUG:root:4386 Executing clock_gettime(0x1, 0x107fae6c) at 0x40048984 from 0x400680e5
# DEBUG:root:4386 syscall clock_gettime returned 0x0
# DEBUG:root:4386 syscall 322 lr=0x4001c93d
# DEBUG:root:4386 Executing openat(0xffffff9c, 0x40074fa2, 0xa0000, 0x0) at 0x400483d8 from 0x4001c93d
# DEBUG:root:4386 syscall openat returned 0x3e8
# DEBUG:root:4386 syscall 192 lr=0x40020a3d
# DEBUG:root:4386 Executing mmap2(0x0, 0x80000, 0x3, 0x22, 0xffffffff, 0x0) at 0x400483b4 from 0x40020a3d
# DEBUG:root:mmap return 0x70A00000
# DEBUG:root:4386 syscall mmap2 returned 0x70a00000
# DEBUG:root:4386 syscall 220 lr=0x40020a6d
# DEBUG:root:4386 Executing madvise(0x70a00000, 0x80000, 0xc) at 0x400490fc from 0x40020a6d
# DEBUG:root:4386 syscall madvise returned 0x0
# DEBUG:root:4386 syscall 172 lr=0x4006818b
# DEBUG:root:4386 Executing prctl(0x53564d41, 0x0, 0x70a00000, 0x80000, 0x40078469) at 0x40049328 from 0x4006818b
# DEBUG:root:prctl: option=0x53564d41 arg2=0 arg3=70a00000 arg4=80000 arg5=40078469
# DEBUG:root:4386 syscall 197 lr=0x4003dcb7
# DEBUG:root:4386 Executing fstat64(0x3e8, 0x107fbe38) at 0x40048bd4 from 0x4003dcb7
# DEBUG:root:4386 syscall fstat64 returned 0x0
# DEBUG:root:4386 syscall 54 lr=0x4001ab13
# DEBUG:root:4386 Executing ioctl(0x3e8, 0x5401, 0x107fbe88, 0x0, 0x70a0300c, 0x1000) at 0x4004835c from 0x4001ab13
# DEBUG:root:ioctl: fd=0x3e8 cmd=0x5401 arg1=0x107fbe88
# DEBUG:root:4386 syscall ioctl returned -0x19
# DEBUG:root:4386 syscall 3 lr=0x4004e939
# DEBUG:root:4386 Executing read(0x3e8, 0x70a08000, 0x1000) at 0x40049420 from 0x4004e939
# DEBUG:root:4386 syscall read returned 0x4
# DEBUG:root:4386 syscall 263 lr=0x400680e5
# DEBUG:root:4386 Executing clock_gettime(0x1, 0x107fbd64) at 0x40048984 from 0x400680e5
# DEBUG:root:4386 syscall clock_gettime returned 0x0
# DEBUG:root:4386 syscall 6 lr=0x40019bab
# DEBUG:root:4386 Executing close(0x3e8) at 0x40048024 from 0x40019bab
# DEBUG:root:4386 syscall close returned 0x0
# DEBUG:root:4386 syscall 263 lr=0x400680e5
# DEBUG:root:4386 Executing clock_gettime(0x1, 0x107fbd54) at 0x40048984 from 0x400680e5
# DEBUG:root:4386 syscall clock_gettime returned 0x0
# DEBUG:root:4386 syscall 125 lr=0x40016cb3
# DEBUG:root:4386 Executing mprotect(0x40088000, 0x1000, 0x3) at 0x40049200 from 0x40016cb3
# DEBUG:root:4386 syscall mprotect returned 0x0
# DEBUG:root:4386 syscall 125 lr=0x40016ccb
# DEBUG:root:4386 Executing mprotect(0x40088000, 0x1000, 0x1) at 0x40049200 from 0x40016ccb
# DEBUG:root:4386 syscall mprotect returned 0x0
# DEBUG:androidemu.native.sym_hooks.libdl_sym:[+] dlopen('libnetd_client.so', flags=0)
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# DEBUG:root:4386 syscall 240 lr=0x400478cf
# DEBUG:root:4386 Executing futex(0x40087018, 0x81, 0x7fffffff, 0x0, 0x0, 0x0) at 0x400174f8 from 0x400478cf
# DEBUG:root:futex_wake call op=0x00000081 uaddr=0x40087018 val=0x7FFFFFFF
# DEBUG:root:4386 syscall futex returned 0x0
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# INFO:androidemu.internal.linker:[Linker] Request to load: libc.so (do_init=False) (main=False)
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib/libc.so (do_init=True) (main=True)
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# [*] Result arm32 'ro.build.version.release': 7.1.2


# INFO:root:process pid:4386
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# DEBUG:androidemu.internal.bionic.tls_factory:[*] Creating TLS backend for arch: ARM64
# DEBUG:androidemu.native.symbol_hooks:[+] Symbol hooks initialized
# INFO:androidemu.internal.linker:[Linker] Request to load: system/lib64/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# DEBUG:androidemu.internal.linker:  [Load] Parsing libc.so
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0x0 size: 0xb6a0c
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0xb8520 size: 0x10340
# DEBUG:androidemu.utils.memory.memory_helpers:[+] mem_map success: 0x40000000 - 0x400c9000 (size: 0xc9000)
# DEBUG:androidemu.internal.linker:[*] ELF mapped to 0x40000000. Size: 0xc9000. Bias: 0x40000000. Segments: 2. Min: 0x0, Max: 0xc8860
# DEBUG:androidemu.internal.linker:[*] soinfo: 0x20000000 for vfs//system/lib64/libc.so. Next: 0x20000038. Size: 0x38.
# DEBUG:androidemu.internal.linker:  [Load] Parsing libdl.so
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0x0 size: 0x93c
# DEBUG:androidemu.internal.elf_reader:Parsed segment LOAD: 0x1e10 size: 0x1f8
# DEBUG:androidemu.utils.memory.memory_helpers:[+] mem_map success: 0x400d0000 - 0x400d3000 (size: 0x3000)
# DEBUG:androidemu.internal.linker:[*] ELF mapped to 0x400d0000. Size: 0x3000. Bias: 0x400d0000. Segments: 2. Min: 0x0, Max: 0x2008
# DEBUG:androidemu.internal.linker:[*] soinfo: 0x20000038 for vfs//system/lib64/libdl.so. Next: 0x20000070. Size: 0x38.
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrapping Modern Layout
# DEBUG:androidemu.internal.bionic.arm64.dtv_builder:[DTV-ARM64] Built at 0x2004000
# DEBUG:androidemu.internal.bionic.arm64.pthread_builder:[PThread-ARM64] Built at 0x2004210. TID: 4387, DTV: 0x2004000 at +0x60
# INFO:androidemu.internal.bionic.arm64.tls_bootstrap:[TLS-ARM64] Bootstrap Done. TP=0x2000000, KAB=0x2004ce8, DTV=0x2004000, Pthread=0x2004210
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: -0x2000000
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# DEBUG:androidemu.internal.linker:  [Reloc] Applying to libc.so
# DEBUG:androidemu.internal.linker:  [Reloc] Relocations: 1791. is_64: 1. Bias: 0x40000000
# DEBUG:androidemu.internal.linker:  [Reloc] Applying to libdl.so
# DEBUG:androidemu.internal.linker:  [Reloc] Relocations: 4. is_64: 1. Bias: 0x400d0000
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# DEBUG:root:4386 syscall 226 lr=0x000000004001fbf8
# DEBUG:root:4386 Executing mprotect(0x400c1000, 0x1000, 0x1) at 0x000000004006af40
# DEBUG:root:4386 syscall 226 lr=0x000000004001fc10
# DEBUG:root:4386 Executing mprotect(0x400c1000, 0x1000, 0x3) at 0x000000004006af40
# DEBUG:root:4386 syscall 226 lr=0x000000004001fc44
# DEBUG:root:4386 Executing mprotect(0x400c1000, 0x1000, 0x1) at 0x000000004006af40
# DEBUG:root:4386 syscall 79 lr=0x000000004002759c
# DEBUG:root:4386 Executing newfstatat(0xffffff9c, 0x400be0a4, 0x107fbb88, 0x0) at 0x000000004006ab50
# DEBUG:root:4386 syscall 56 lr=0x0000000040022b10
# DEBUG:root:4386 Executing openat(0xffffff9c, 0x400be0a4, 0x88000, 0x0) at 0x000000004006a688
# INFO:root:open [vfs//dev/__properties__][0x88000] return fd 3
# DEBUG:root:4386 syscall 80 lr=0x000000004002734c
# DEBUG:root:4386 Executing fstat(0x3, 0x107fbab8) at 0x000000004006ab38
# DEBUG:root:4386 syscall 222 lr=0x0000000040027440
# DEBUG:root:4386 Executing mmap(0x0, 0x20000, 0x1, 0x1, 0x3, 0x0) at 0x000000004006af10
# DEBUG:root:mmap return 0x0000000070100000
# DEBUG:root:4386 syscall 57 lr=0x000000004001dd6c
# DEBUG:root:4386 Executing close(0x3) at 0x000000004006a448
# DEBUG:root:4386 syscall 214 lr=0x000000004001d714
# DEBUG:root:4386 Executing brk(0x0) at 0x000000004006a538
# DEBUG:androidemu.kernel.syscalls.syscall_memory.memory_syscall_handler: Initialized brk heap at 0x70120000 - 0x70920000
# DEBUG:root:4386 syscall 222 lr=0x0000000040090ca8
# DEBUG:root:4386 Executing mmap(0x0, 0x200000, 0x3, 0x22, 0xffffffff, 0x0) at 0x000000004006af10
# DEBUG:root:mmap return 0x0000000070920000
# DEBUG:root:4386 syscall 167 lr=0x0000000040090d04
# DEBUG:root:4386 Executing prctl(0x53564d41, 0x0, 0x70920000, 0x200000, 0x4009c722) at 0x000000004006b000
# DEBUG:root:prctl: option=0x53564d41 arg2=0 arg3=70920000 arg4=200000 arg5=4009c722
# DEBUG:root:4386 syscall 215 lr=0x0000000040090d98
# DEBUG:root:4386 Executing munmap(0x70920000, 0x200000) at 0x000000004006afa0
# DEBUG:root:4386 syscall 222 lr=0x0000000040090ca8
# DEBUG:root:4386 Executing mmap(0x0, 0x3ff000, 0x3, 0x22, 0xffffffff, 0x0) at 0x000000004006af10
# DEBUG:root:mmap return 0x0000000070920000
# DEBUG:root:4386 syscall 167 lr=0x0000000040090d04
# DEBUG:root:4386 Executing prctl(0x53564d41, 0x0, 0x70920000, 0x3ff000, 0x4009c722) at 0x000000004006b000
# DEBUG:root:prctl: option=0x53564d41 arg2=0 arg3=70920000 arg4=3ff000 arg5=4009c722
# DEBUG:root:4386 syscall 215 lr=0x0000000040090e40
# DEBUG:root:4386 Executing munmap(0x70920000, 0xe0000) at 0x000000004006afa0
# DEBUG:root:4386 syscall 215 lr=0x0000000040090e98
# DEBUG:root:4386 Executing munmap(0x70c00000, 0x11f000) at 0x000000004006afa0
# DEBUG:root:4386 syscall 113 lr=0x0000000040090c18
# DEBUG:root:4386 Executing clock_gettime(0x1, 0x107fa9a8) at 0x000000004006a550
# DEBUG:root:4386 syscall 56 lr=0x0000000040022b10
# DEBUG:root:4386 Executing openat(0xffffff9c, 0x4009922f, 0x80000, 0x0) at 0x000000004006a688
# DEBUG:root:4386 syscall 222 lr=0x0000000040090ca8
# DEBUG:root:4386 Executing mmap(0x0, 0x200000, 0x3, 0x22, 0xffffffff, 0x0) at 0x000000004006af10
# DEBUG:root:mmap return 0x0000000070C00000
# DEBUG:root:4386 syscall 167 lr=0x0000000040090d04
# DEBUG:root:4386 Executing prctl(0x53564d41, 0x0, 0x70c00000, 0x200000, 0x4009c722) at 0x000000004006b000
# DEBUG:root:prctl: option=0x53564d41 arg2=0 arg3=70c00000 arg4=200000 arg5=4009c722
# DEBUG:root:4386 syscall 80 lr=0x00000000400586a8
# DEBUG:root:4386 Executing fstat(0x3e8, 0x107fb908) at 0x000000004006ab38
# DEBUG:root:4386 syscall 29 lr=0x000000004001fb0c
# DEBUG:root:4386 Executing ioctl(0x3e8, 0x5401, 0x107fb8b0, 0x0, 0x0, 0x1) at 0x000000004006a670
# DEBUG:root:ioctl: fd=0x3e8 cmd=0x5401 arg1=0x107fb8b0
# DEBUG:root:4386 syscall 63 lr=0x0000000040072bd4
# DEBUG:root:4386 Executing read(0x3e8, 0x70c0f000, 0x1000) at 0x000000004006b0c0
# DEBUG:root:4386 syscall 113 lr=0x0000000040090c18
# DEBUG:root:4386 Executing clock_gettime(0x1, 0x107fb798) at 0x000000004006a550
# DEBUG:root:4386 syscall 57 lr=0x000000004001dd6c
# DEBUG:root:4386 Executing close(0x3e8) at 0x000000004006a448
# DEBUG:root:4386 syscall 113 lr=0x0000000040090c18
# DEBUG:root:4386 Executing clock_gettime(0x1, 0x107fb778) at 0x000000004006a550
# DEBUG:root:4386 syscall 226 lr=0x000000004001a710
# DEBUG:root:4386 Executing mprotect(0x400c1000, 0x1000, 0x3) at 0x000000004006af40
# DEBUG:root:4386 syscall 226 lr=0x000000004001a734
# DEBUG:root:4386 Executing mprotect(0x400c1000, 0x1000, 0x1) at 0x000000004006af40
# DEBUG:androidemu.native.sym_hooks.libdl_sym:[+] dlopen('libnetd_client.so', flags=2)
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# DEBUG:root:4386 syscall 98 lr=0x0000000040069230
# DEBUG:root:4386 Executing futex(0x400c0030, 0x81, 0x7fffffff, 0x0, 0x0, 0x0) at 0x000000004001bf30
# DEBUG:root:futex_wake call op=0x00000081 uaddr=0x400C0030 val=0x7FFFFFFF
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# INFO:androidemu.internal.linker:[Linker] Request to load: libc.so (do_init=False) (main=False)
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib64/libc.so (do_init=True) (main=True)
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# [*] sysconf: 200809
# [*] Result arm64 'ro.build.version.release': 7.1.2
# .
# ----------------------------------------------------------------------
# Ran 1 test in 0.202s

# OK
#          170731 function calls (170483 primitive calls) in 0.206 seconds

#    Ordered by: cumulative time
#    List reduced from 799 to 40 due to restriction <40>

#    ncalls  tottime  percall  cumtime  percall filename:lineno(function)
#         1    0.000    0.000    0.206    0.206 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\main.py:65(__init__)
#         1    0.000    0.000    0.203    0.203 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\main.py:246(runTests)
#         1    0.000    0.000    0.203    0.203 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\runner.py:151(run)
#       2/1    0.000    0.000    0.202    0.202 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\suite.py:83(__call__)
#       2/1    0.000    0.000    0.202    0.202 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\suite.py:102(run)
#         1    0.000    0.000    0.202    0.202 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\case.py:735(__call__)
#         1    0.000    0.000    0.202    0.202 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\case.py:641(run)
#         1    0.000    0.000    0.202    0.202 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\case.py:632(_callTestMethod)
#         1    0.000    0.000    0.202    0.202 c:/Users/Kirill/Desktop/androidemu/test_getprop.py:69(test_getprop)
#         2    0.000    0.000    0.197    0.099 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:151(__init__)
#         6    0.000    0.000    0.167    0.028 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:117(load_module)
#         2    0.000    0.000    0.166    0.083 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:141(__init_syslibs)
#         2    0.000    0.000    0.166    0.083 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:133(_pipeline_load_executable)
#        25    0.000    0.000    0.066    0.003 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:261(call_native)
#        25    0.000    0.000    0.066    0.003 c:\Users\Kirill\Desktop\androidemu\androidemu\scheduler.py:156(call_native)
#        25    0.000    0.000    0.065    0.003 c:\Users\Kirill\Desktop\androidemu\androidemu\scheduler.py:139(exec)
#       8/6    0.000    0.000    0.064    0.011 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:189(_load_recursive)
#         4    0.000    0.000    0.063    0.016 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:283(_initialize_graph)
#       6/4    0.000    0.000    0.063    0.016 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:287(visit)
#         4    0.000    0.000    0.063    0.016 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:300(_call_constructors)
#        25    0.000    0.000    0.062    0.002 c:\Users\Kirill\Desktop\androidemu\androidemu\scheduler.py:164(__run_scheduler_loop)
#        26    0.022    0.001    0.061    0.002 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\site-packages\unicorn\unicorn.py:315(emu_start)
#         4    0.007    0.002    0.055    0.014 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\elf_reader.py:11(__init__)
#         4    0.042    0.011    0.046    0.011 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\elf_reader.py:93(_parse_functions)
#        61    0.000    0.000    0.039    0.001 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\site-packages\unicorn\unicorn.py:492(_hook_intr_cb)
#        61    0.000    0.000    0.038    0.001 c:\Users\Kirill\Desktop\androidemu\androidemu\kernel\syscalls\interrupt_handler.py:25(_hook_interrupt)
#         4    0.009    0.002    0.037    0.009 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:243(_relocate_module)
#       274    0.000    0.000    0.034    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\logging\__init__.py:1565(_log)
#       238    0.000    0.000    0.030    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\logging\__init__.py:1424(debug)
#       274    0.000    0.000    0.025    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\logging\__init__.py:1591(handle)
#       274    0.001    0.000    0.025    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\logging\__init__.py:1645(callHandlers)
#       194    0.000    0.000    0.024    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\logging\__init__.py:2084(debug)
#       274    0.000    0.000    0.024    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\logging\__init__.py:941(handle)
#       274    0.001    0.000    0.023    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\logging\__init__.py:1073(emit)
#        32    0.001    0.000    0.022    0.001 c:\Users\Kirill\Desktop\androidemu\androidemu\kernel\syscalls\syscall_handlers.py:34(_handle_syscall)
#       283    0.020    0.000    0.020    0.000 {method 'write' of '_io.TextIOWrapper' objects}
#         2    0.000    0.000    0.019    0.010 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:57(__add_classes)
#        29    0.000    0.000    0.017    0.001 c:\Users\Kirill\Desktop\androidemu\androidemu\kernel\syscalls\syscall_handlers.py:73(_handle_syscall64)
#        64    0.000    0.000    0.012    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\importlib\__init__.py:109(import_module)
#        64    0.000    0.000    0.012    0.000 <frozen importlib._bootstrap>:1002(_gcd_import)