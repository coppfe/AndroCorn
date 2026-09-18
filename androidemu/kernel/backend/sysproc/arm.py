from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu import Emulator
    
    from androidemu.utils.tls import BionicTLSUtils


class ARMSyscalls:
    def __init__(self) -> None:
        pass

    def _ARM_set_tls(self, emu: 'Emulator', tls_ptr: int) -> int:
        emu.tls_utils.set_tls(tls_ptr)
        return 0

    # BUG: ARM Cacheflush is mocked but in Unicorn 2.x as i see JIT now is not correctly invalidate cache. Maybe cacheflush is supposed to be implemented
    # but if you invalidate cache performance will be... bad. very