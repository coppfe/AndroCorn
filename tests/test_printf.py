import unittest
from androidemu.emulator import Emulator
from androidemu.const import emu_const

class TestLibcPrintfCall(unittest.TestCase):

    def setUp(self):
        self.emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM64, muti_task=True)

    def tearDown(self):
        del self.emulator

    def test_printf_with_int_and_string(self):
        emulator = self.emulator
        vfs_path = emulator.vfs_root

        libc = emulator.load_library(f"{vfs_path}/system/lib64/libc.so", do_init=True)

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
# INFO:androidemu.internal.bionic.arm32.tls_bootstrap:TLS 7.1 Ready. TP: 0x2000000 DTV: 0x2005000, Pthread: 0x2005610
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# DEBUG:androidemu.internal.linker:  [Reloc] Applying to libc.so
# DEBUG:androidemu.internal.linker:  [Reloc] Relocations: 2125. is_64: 0. Bias: 0x40000000
# DEBUG:androidemu.internal.linker:  [Reloc] Applying to libdl.so
# DEBUG:androidemu.internal.linker:  [Reloc] Relocations: 17. is_64: 0. Bias: 0x40090000
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] Initializing libdl.so
# INFO:androidemu.internal.linker:  [Init] Initializing libc.so
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
# DEBUG:root:open [/dev/__properties__] HostFD:3 -> GuestFD:3
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
# DEBUG:root:VFS: Physically closed host FD 3
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
# DEBUG:androidemu.native.sym_hooks.libdl_sym:[+] dlopen('libnetd_client.so', flags=0x0)
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
# INFO:androidemu.internal.linker:[Linker] Request to load: vfs/system/lib/libc.so (do_init=True) (main=False)
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# [*] Calling printf via emulator...
# DEBUG:root:4386 syscall 197 lr=0x4003dcb7
# DEBUG:root:4386 Executing fstat64(0x1, 0x107fb8c8) at 0x40048bd4 from 0x4003dcb7
# DEBUG:root:4386 syscall fstat64 returned 0x0
# DEBUG:root:4386 syscall 240 lr=0x400478cf
# DEBUG:root:4386 Executing futex(0x40089078, 0x81, 0x7fffffff, 0x0, 0x0, 0x0) at 0x400174f8 from 0x400478cf
# DEBUG:root:futex_wake call op=0x00000081 uaddr=0x40089078 val=0x7FFFFFFF
# DEBUG:root:4386 syscall futex returned 0x0
# DEBUG:root:Main scheduler finished.
# [*] printf returned: 37 bytes written
# [*] Forcing fflush(0)...
# DEBUG:root:4386 syscall 4 lr=0x4004e999
# DEBUG:root:4386 Executing write(0x1, 0x70a0f000, 0x25) at 0x40049d74 from 0x4004e999
# Hello AndroCorn, your number is 2026
# DEBUG:root:4386 syscall write returned 0x25
# DEBUG:root:Main scheduler finished.
# DEBUG:root:4386 syscall 263 lr=0x400680e5
# DEBUG:root:4386 Executing clock_gettime(0x1, 0x107fbe5c) at 0x40048984 from 0x400680e5
# DEBUG:root:4386 syscall clock_gettime returned 0x0
# DEBUG:root:Main scheduler finished.
# DEBUG:root:Main scheduler finished.
# .
# ----------------------------------------------------------------------
# Ran 1 test in 0.101s

# OK