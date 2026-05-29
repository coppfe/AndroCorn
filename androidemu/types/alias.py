import platform

from typing import TYPE_CHECKING

from .numbers import NumType
from ..const.emu_const import ARCH_ARM32

_current_arch = ARCH_ARM32
_os = platform.system()

def set_types(arch: int):
    global _current_arch
    _current_arch = arch
    # _os = platform.system()

class DynType:
    def __init__(self, arm32_type, arm64_type):
        self.arm32_type = arm32_type
        self.arm64_type = arm64_type

    def _get_current(self):
        return self.arm32_type if _current_arch == ARCH_ARM32 else self.arm64_type

    def __eq__(self, other):
        return self._get_current() == other
        
    def __hash__(self):
        return hash(self._get_current())

    def __repr__(self):
        return str(self._get_current())
    
    @property
    def size(self) -> int:
        current_type = self._get_current()
        
        if current_type in (NumType.S32, NumType.U32):
            return 4
        elif current_type in (NumType.S64, NumType.U64):
            return 8
            
        # return 4 if _current_arch == ARCH_ARM32 else 8 # ptr_t


if TYPE_CHECKING:
    class int32_t(DynType)   : pass
    class uint32_t(DynType)  : pass
    class int64_t(DynType)   : pass
    class uint64_t(DynType)  : pass
    class off_t(DynType)     : pass
    class size_t(DynType)    : pass
    class ptr_t(DynType)     : pass
else:
    int32_t  = DynType(NumType.S32, NumType.S32)
    uint32_t = DynType(NumType.U32, NumType.U32)
    int64_t  = DynType(NumType.S64, NumType.S64)
    uint64_t = DynType(NumType.U64, NumType.U64)

    off_t    = DynType(NumType.S32, NumType.S64)
    size_t   = DynType(NumType.U32, NumType.U64)
    ptr_t    = DynType(NumType.U32, NumType.U64)