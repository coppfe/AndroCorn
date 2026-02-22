import logging
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
from ....utils.struct_writer import StructWriter
from ....const import linux
from .dtv_builder import DTVBuilderARM64
from .pthread_builder import PThreadBuilderARM64
from ..tls_modules import TLSModuleLoader
from ..tls_bionic import BionicTLS

logger = logging.getLogger(__name__)

class BionicTLS_ARM64(BionicTLS):

    def __init__(self, emu):
        self.emu = emu
        self.mu = emu.mu
        self.ptr_sz = 8
        
        from ....config import TLS_BASE
        self.counter_memory = TLS_BASE

        self.tp = 0
        self.dtv = 0
        self.pthread_internal = 0
        self.errno_ptr = 0

        self.dtv_builder = DTVBuilderARM64(emu, self)
        self.pthread_builder = PThreadBuilderARM64(emu, self)

        # Stack guard / AT_RANDOM
        self.at_rand = b"\x42" * 16

    def mem_reserve(self, size: int, align: int = 0x10) -> int:
        from ....config import PAGE_SIZE
        base = (self.counter_memory + (align - 1)) & ~(align - 1)
        end = base + size
        map_start = base & ~(PAGE_SIZE - 1)
        map_end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        try:
            self.mu.mem_map(map_start, map_end - map_start)
        except: 
            pass
        self.counter_memory = end
        return base

    def bootstrap(self, phdr_addr, phnum, entry_point):
        logger.info("[TLS-ARM64] Bootstrapping Modern Layout")

        self.tp = self.mem_reserve(0x1000, align=0x1000)

        # Bionic TLS (Slot 5)
        bionic_tls = self.mem_reserve(0x3000)
        self.mu.mem_write(bionic_tls, b"\x00" * 0x3000)

        # DTV & Pthread
        self.dtv = self.dtv_builder.build()
        self.pthread_internal = self.pthread_builder.build(
            tls_slots_ptr=self.tp,
            bionic_tls_ptr=bionic_tls,
            dtv_ptr=self.dtv
        )
        self.errno_ptr = self.pthread_internal + 0x100

        # Kernel Argument Block
        kab_base = self._init_kernel_args(phdr_addr, phnum, entry_point)

        self._write_ptr(self.tp + 0x00, self.tp)               # Slot 0: SELF
        self._write_ptr(self.tp + 0x08, self.pthread_internal) # Slot 1: pthread_internal / TID
        self._write_ptr(self.tp + 0x10, self.dtv)             # Slot 2: DTV
        self._write_ptr(self.tp + 0x18, kab_base)             # Slot 3: Kernel Argument Block (auxv/argc/argv)
        # Slot 4: Reserved / OpenGL / Mapping
        self._write_ptr(self.tp + 0x20, 0)
        # Slot 5: Bionic TLS
        self._write_ptr(self.tp + 0x28, bionic_tls)
        # Slot 6: Stack Guard
        rand_ptr = self.mem_reserve(16, align=16)
        self.mu.mem_write(rand_ptr, self.at_rand)
        self._write_ptr(self.tp + 0x30, rand_ptr)
        # Slot 7: errno
        self._write_ptr(self.tp + 0x38, self.errno_ptr)

        self.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, self.tp)
        
        logger.info(f"[TLS-ARM64] Bootstrap Done. TP={hex(self.tp)}, KAB={hex(kab_base)}, DTV={hex(self.dtv)}, Pthread={hex(self.pthread_internal)}")

    def _init_kernel_args(self, phdr_addr, phnum, entry_point):
        writer = StructWriter(self.emu, self.mem_reserve(0x4000))

        # 1. bin_name
        bin_name_ptr = writer.write_utf8("/system/bin/app_process")

        # 2. Stack guard / AT_RANDOM
        rand_ptr = writer.reserve_bytes(16)
        self.mu.mem_write(rand_ptr, self.at_rand)

        # 3. argv
        argv_ptr = writer.reserve(16)
        self._write_ptr(argv_ptr, bin_name_ptr)
        self._write_ptr(argv_ptr + 8, 0)

        # 4. envp
        env = {
            "ANDROID_DATA":"/data",
            "MKSH":"/system/bin/sh",
            "HOME":"/data",
            "USER":"shell",
            "ANDROID_ROOT":"/system",
            "SHELL":"/system/bin/sh",
            "ANDROID_BOOTLOGO":"1",
            "TMPDIR":"/data/local/tmp",
            "ANDROID_ASSETS":"/system/app",
            "HOSTNAME":"bullhead",
            "EXTERNAL_STORAGE":"/sdcard",
            "ANDROID_STORAGE":"/storage",
        }

        env_str_ptrs = []
        for k, v in env.items():
            s = f"{k}={v}"
            ptr = writer.write_utf8(s)
            env_str_ptrs.append(ptr)

        envp_ptr = writer.reserve((len(env_str_ptrs) + 1) * 8)
        for i, ptr in enumerate(env_str_ptrs):
            self._write_ptr(envp_ptr + i*8, ptr)
        self._write_ptr(envp_ptr + len(env_str_ptrs)*8, 0)  # NULL-terminated

        # 5. auxv
        auxv_ptr = writer.reserve(64)
        auxv = [
            (linux.AT_PHDR, phdr_addr),
            (linux.AT_PHNUM, phnum),
            (linux.AT_PHENT, 32),
            (linux.AT_PAGESZ, 4096),
            (linux.AT_ENTRY, entry_point),
            (linux.AT_HWCAP, 0x3FF),
            (linux.AT_RANDOM, rand_ptr),
            (linux.AT_NULL, 0)
        ]
        curr_auxv = auxv_ptr
        for k, v in auxv:
            self._write_ptr(curr_auxv, k)
            self._write_ptr(curr_auxv + 8, v)
            curr_auxv += 16 

        # 6. Kernel Argument Block
        kab_base = writer.reserve(32)
        self._write_ptr(kab_base + 0, 1)          # argc
        self._write_ptr(kab_base + 8, argv_ptr)   # argv
        self._write_ptr(kab_base + 16, envp_ptr)  # envp
        self._write_ptr(kab_base + 24, auxv_ptr)  # auxv

        return kab_base

    def setup_static_tls(self, reader, bias):
        loader = TLSModuleLoader(self.emu, self)
        module_id = loader.register_module(reader, bias)
        tls_block = self.dtv_builder.get_tls_block(module_id)
        return tls_block - self.tp

    def _write_ptr(self, addr, val):
        if isinstance(val, int):
            self.mu.mem_write(addr, val.to_bytes(8, 'little'))
        elif isinstance(val, bytes):
            self.mu.mem_write(addr, val)
        else:
            raise TypeError(f"_write_ptr: unsupported type {type(val)}")