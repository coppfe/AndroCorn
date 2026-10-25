import logging
import struct

from .modules import TLSModuleLoader
from ..dtv_builder import DTVBuilder
from ..pthread_builder import PThreadBuilder

from ....const import linux
from ....data.layout import PAGE_SIZE, TLS_BASE
from ....utils.memory.struct_writer import StructWriter
from ....types.alias import ptr_t

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.utils.memory.map import MemoryMap
    from androidemu.core.registers import RegistersMapping

logger = logging.getLogger(__name__)


class BionicTLSInitialization:
    """
    Bionic TLS Android 7
    """

    ENVIRONMENT = (
        "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
        "ANDROID_DATA=/data",
        "MKSH=/system/bin/sh",
        "HOME=/data",
        "USER=shell",
        "ANDROID_ROOT=/system",
        "SHELL=/system/bin/sh",
        "ANDROID_BOOTLOGO=1",
        "TMPDIR=/data/local/tmp",
        "ANDROID_ASSETS=/system/app",
        "HOSTNAME=bullhead",
        "EXTERNAL_STORAGE=/sdcard",
        "ANDROID_STORAGE=/storage"
    )

    def __init__(self, memory: 'MemoryMap', registers: 'RegistersMapping'):
        self.ptr_size = ptr_t.size
        self.counter_memory = TLS_BASE

        self.memory = memory
        self.registers = registers

        self.dtv_builder = DTVBuilder(memory, self)
        self.pthread_builder = PThreadBuilder(memory)

        if self.ptr_size == 4:
            self._phent = 32
            self._hwcap = 0x3FF
            self._struct_ptr = struct.Struct("<I")
            self._kab_size = 16
            self._tls_packer = struct.Struct("<IIII")
            self._kab_packer = self._tls_packer
        else:
            self._phent = 56
            self._hwcap = 0xFF
            self._struct_ptr = struct.Struct("<Q")
            self._kab_size = 32
            self._tls_packer = struct.Struct("<QQQQQQ")
            self._kab_packer = struct.Struct("<QQQQ")

        self._rand = b'\42' * (self.ptr_size - 1) + b'\x00'
        self._rand_int = self._struct_ptr.unpack(self._rand)[0]

    def bootstrap(self, phdr_addr: int, phnum: int, entry_point: int) -> None:
        logger.info("[TLS-7.1] Bootstrapping Legacy Layout")

        self.tp = self.memory.static_alloc(PAGE_SIZE, addr=self.counter_memory, align=PAGE_SIZE)
        self.counter_memory = self.tp + PAGE_SIZE

        self.kernel_args_base = self._init_kernel_args(phdr_addr, phnum, entry_point)
        self.dtv = self.dtv_builder.build()
        self.pthread_internal = self.pthread_builder.build()

        if self.ptr_size == 4:
            # 0x0: Self
            # 0x4: pthread
            # 0x8: errno (0)
            # 0xC: KAB
            tls_bytes = self._tls_packer.pack(
                self.tp,
                self.pthread_internal,
                0,
                self.kernel_args_base
            )
            self.memory.write_bytes(self.tp, tls_bytes)
            self.registers.v_reg_9 = self.tp
        else:
            # 0x0: Self
            # 0x8: pthread
            # 0x10: errno
            # 0x18: KAB
            # 0x20: res
            # 0x28: Canary

            tls_bytes = self._tls_packer.pack(
                self.tp,
                self.pthread_internal,
                0,
                self.kernel_args_base,
                0,
                self._rand_int
            )
            self.memory.write_bytes(self.tp, tls_bytes)

        self.registers.v_tls = self.tp
        logger.info("TLS 7.1 Ready. TP: %#x DTV: %#x, Pthread: %#x", self.tp, self.dtv, self.pthread_internal)

    def setup_static_tls(self, reader, bias: int) -> int:
        loader = TLSModuleLoader(self.memory, self)
        module_id = loader.register_module(reader)
        if module_id == 0:
            return 0
        return self.dtv_builder.get_tls_block(module_id) - self.tp

    def _init_kernel_args(self, phdr_addr: int, phnum: int, entry_point: int) -> int:
        reserver = self.memory
        addr = reserver.static_alloc(0x4000, addr=self.counter_memory)
        self.counter_memory = addr + 0x4000

        writer = StructWriter(self.memory)
        bin_name_ptr = writer.write_utf8("/system/bin/app_process")

        # AT_RANDOM
        rand_ptr = reserver.dynamic_alloc(self.ptr_size, is_ptr_array=True)
        self.memory.write_bytes(rand_ptr, self._rand)

        # argv (2 fields + NULL)
        argv_ptr = reserver.dynamic_alloc(self.ptr_size * 2)
        self.memory.write_bytes(argv_ptr, self._struct_ptr.pack(bin_name_ptr) + self._struct_ptr.pack(0))

        # env
        env_ptrs_bytes = b"".join(self._struct_ptr.pack(writer.write_utf8(s)) for s in self.ENVIRONMENT)
        envp_ptr = reserver.dynamic_alloc(len(env_ptrs_bytes) + self.ptr_size)
        self.memory.write_bytes(envp_ptr, env_ptrs_bytes + self._struct_ptr.pack(0))

        auxv = (
            (linux.AT_PHDR, phdr_addr),
            (linux.AT_PHNUM, phnum),
            (linux.AT_PHENT, self._phent),
            (linux.AT_PAGESZ, PAGE_SIZE),
            (linux.AT_ENTRY, entry_point),
            (linux.AT_HWCAP, self._hwcap),
            (linux.AT_RANDOM, rand_ptr),
            (linux.AT_NULL, 0)
        )

        auxv_bytes = b"".join(self._struct_ptr.pack(k) + self._struct_ptr.pack(v) for k, v in auxv)
        auxv_ptr = reserver.static_alloc(len(auxv_bytes))
        self.memory.write_bytes(auxv_ptr, auxv_bytes)

        kab_bytes = self._kab_packer.pack(1, argv_ptr, envp_ptr, auxv_ptr)
        kab_base = reserver.dynamic_alloc(self._kab_size)
        self.memory.write_bytes(kab_base, kab_bytes)

        return kab_base