import logging
import os

from unicorn.arm_const import *
from ....utils.struct_writer import StructWriter
from ....const import linux
from .dtv_builder import DTVBuilderARM32
from .pthread_builder import PThreadBuilderARM32
from ..tls_modules import TLSModuleLoader

from ..tls_bionic import BionicTLS

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ....emulator import Emulator

logger = logging.getLogger(__name__)

class BionicTLS_ARM32(BionicTLS):
    """
    Bionic TLS ARM32 Android 7.1
    """

    def __init__(self, emu: 'Emulator'):
        super().__init__(emu)

        self.dtv_builder = DTVBuilderARM32(emu, self)
        self.pthread_builder = PThreadBuilderARM32(emu, self)

        # self.at_rand = b'0\x1bK\xf1\xef\xc8)\xc3\xce>\x94Q\xcf\x98\xff3'
        self.at_rand = b"\42" * 16
        
    def mem_reserve(self, size: int, align: int = 0x10) -> int:
        from ....config import PAGE_SIZE
        base = (self.counter_memory + (align - 1)) & ~(align - 1)
        end = base + size
        map_start = base & ~(PAGE_SIZE - 1)
        map_end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        try:
            self.mu.mem_map(map_start, map_end - map_start)
        except: pass
        self.counter_memory = end
        return base

    def bootstrap(self, phdr_addr, phnum, entry_point):
        logger.info("[TLS-7.1-ARM32] Bootstrapping Legacy Layout")

        self.tp = self.mem_reserve(0x1000, align=0x1000)

        self.kernel_args_base = self._init_kernel_args(phdr_addr, phnum, entry_point)

        self.dtv = self.dtv_builder.build()
        
        bionic_internal_data = self.mem_reserve(0x500) 
        
        self.pthread_internal = self.pthread_builder.build(
            tls_slots_ptr=self.tp,
            bionic_tls_ptr=bionic_internal_data,
            dtv_ptr=self.dtv
        )
        
        self.errno_ptr = self.pthread_internal + 0x100

        # Slot 0: TLS Base pointer (Self)
        self._write_ptr(self.tp + 0x00, self.tp)
        # Slot 1: pthread_t
        self._write_ptr(self.tp + 0x04, self.pthread_internal)
        # Slot 2: __errno
        self._write_ptr(self.tp + 0x08, self.errno_ptr)
        # Slot 3: Kernel Argument Block (AUXV, argc, argv)
        self._write_ptr(self.tp + 0x0C, self.kernel_args_base)
        # Slot 4: Stack Guard (SSP)
        self._write_ptr(self.tp + 0x10, self.at_rand)
        # Slot 5: Locale
        self._write_ptr(self.tp + 0x14, 0)
        # Slot 6: Reserved
        self._write_ptr(self.tp + 0x18, 0)
        # Slot 7: DTV (Dynamic Thread Vector)
        self._write_ptr(self.tp + 0x1C, self.dtv)

        self.mu.reg_write(UC_ARM_REG_R9, self.tp)
        self.mu.reg_write(UC_ARM_REG_R10, self.pthread_internal) # ?
        self.mu.reg_write(UC_ARM_REG_C13_C0_3, self.tp)
        
        logger.info(f"TLS 7.1 Ready. TP: {hex(self.tp)}, DTV: {hex(self.dtv)}, Pthread: {hex(self.pthread_internal)}")

    def setup_static_tls(self, reader, bias):
        loader = TLSModuleLoader(self.emu, self)
        module_id = loader.register_module(reader, bias)
        if module_id == 0:
            return 0
        tls_block = self.dtv_builder.get_tls_block(module_id)
        return tls_block - self.tp

    
    def _init_kernel_args(self, phdr_addr, phnum, entry_point):
        writer = StructWriter(self.emu, self.mem_reserve(0x4000))

        # Kernel args
        bin_name_ptr = writer.write_utf8("/system/bin/app_process")

        # Stack guard / AT_RANDOM
        rand_ptr = writer.reserve_bytes(16)
        self.mu.mem_write(rand_ptr, self.at_rand)

        # argv
        argv_ptr = writer.reserve(8)
        self._write_ptr(argv_ptr, bin_name_ptr)
        self._write_ptr(argv_ptr + 4, 0)

        # envp
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

        envp_ptr = writer.reserve((len(env_str_ptrs) + 1) * 4)
        for i, ptr in enumerate(env_str_ptrs):
            self._write_ptr(envp_ptr + i*4, ptr)
        self._write_ptr(envp_ptr + len(env_str_ptrs)*4, 0)  # NULL-terminated

        # auxv
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
            self._write_ptr(curr_auxv + 4, v)
            curr_auxv += 8

        # Kernel Argument Block
        kab_base = writer.reserve(16)
        self._write_ptr(kab_base + 0, 1)         # argc
        self._write_ptr(kab_base + 4, argv_ptr)  # argv
        self._write_ptr(kab_base + 8, envp_ptr)  # envp
        self._write_ptr(kab_base + 12, auxv_ptr) # auxv

        return kab_base

    def _write_ptr(self, addr, val):
        """
        Пишет указатель или данные в память ARM32 (Unicorn).
        
        - addr: адрес в эмулированной памяти
        - val: int (указатель), bytes (данные)
        """
        if isinstance(val, int):
            self.mu.mem_write(addr, val.to_bytes(4, 'little'))
        elif isinstance(val, bytes):
            self.mu.mem_write(addr, val)
        else:
            raise TypeError(f"_write_ptr: unsupported type {type(val)}")