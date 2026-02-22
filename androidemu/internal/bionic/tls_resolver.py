from typing import TYPE_CHECKING
from ...java.helpers.native_method import native_method

if TYPE_CHECKING:
    from ...emulator import Emulator
    from .tls_bionic import BionicTLS

# not used

class TLSSymbolResolver:
    def __init__(self, emu: 'Emulator', state: 'BionicTLS'):
        self.emu = emu
        self.mu = emu.mu
        self.ptr_sz = emu.get_ptr_size()
        self.state = state

    @native_method
    def tls_get_addr(self, tls_index_ptr: int) -> int:
        """
        tls_index_ptr -> struct { module_id, offset }
        """
        module_id = self._read_ptr(tls_index_ptr)
        offset    = self._read_ptr(tls_index_ptr + self.ptr_sz)

        tls_block = self.state.dtv_builder.get_tls_block(module_id)

        if tls_block == 0:
            tls_block = self._allocate_dynamic_tls(module_id)

            pass 

        return tls_block + offset

    def _allocate_dynamic_tls(self, module_id: int) -> int:
        if not hasattr(self.state, 'modules') or module_id not in self.state.modules:
             raise RuntimeError(f"TLS metadata missing for module {module_id}")

        meta = self.state.modules[module_id]
        memsz = meta["memsz"]
        tdata = meta["tdata"]
        
        addr = self.state.mem_reserve(memsz, align=0x10)

        if tdata:
            self.mu.mem_write(addr, tdata)
        
        tbss_len = memsz - len(tdata)
        if tbss_len > 0:
            self.mu.mem_write(addr + len(tdata), b'\x00' * tbss_len)

        return addr

    def _read_ptr(self, addr):
        return int.from_bytes(self.mu.mem_read(addr, self.ptr_sz), 'little')