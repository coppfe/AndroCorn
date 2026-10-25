from typing import TYPE_CHECKING, Optional, Union

from ..const.emu_const import ARCH_ARM32
from ..const.offsets.arm32 import ARM32_TLS_ERRNO
from ..const.offsets.arm64 import ARM64_TLS_ERRNO

if TYPE_CHECKING:
    from ..core.registers import RegistersMapping
    from .memory.map import MemoryMap


class BionicTLSUtils:
    __slots__ = ("_memory", "_registers", "_errno_offset")

    def __init__(
        self,
        memory: "MemoryMap",
        registers: "RegistersMapping"
    ):
        self._memory = memory
        self._registers = registers

        target_arch = registers._arch
        self._errno_offset = ARM32_TLS_ERRNO if target_arch == ARCH_ARM32 else ARM64_TLS_ERRNO

    def set_errno(self, errno: int) -> int:
        tls = self._registers.v_tls
        if not tls:
            return -1

        slot = tls + self._errno_offset
        self._memory.write_u32(slot, errno & 0xFFFFFFFF)
        return 0

    def get_errno(self) -> int:
        tls = self._registers.v_tls
        if not tls:
            return 0

        slot = tls + self._errno_offset
        return self._memory.read_u32(slot)

    def set_tls(self, tls_ptr: int) -> int:
        self._registers.v_tls = tls_ptr
        return 0

    def get_tls(self) -> int:
        return self._registers.v_tls