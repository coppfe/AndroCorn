import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Tuple
from lief.ELF import Relocation

from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm64_const import UC_ARM64_REG_X0

if TYPE_CHECKING:
    from ..core.emulator import Emulator
    from .module import Module
    from .resolver import SymbolResolver

logger = logging.getLogger(__name__)


class BaseRelocator(ABC):
    def __init__(self, emu: 'Emulator', module: 'Module', resolver: 'SymbolResolver'):
        self.emu = emu
        self.module = module
        self.resolver = resolver
        self.bias = module.bias
        self.tp = emu.tls_state.tp if hasattr(emu, 'tls_state') and emu.tls_state else 0
        
        self.deferred_ifuncs: List[Tuple[int, int, int]] = []

    @abstractmethod
    def relocate_all(self, all_modules: List['Module']) -> None:
        pass

    def _resolve_deferred_ifuncs(self, hwcap: int) -> None:
        mu = self.emu.mu
        reg_arg0 = UC_ARM64_REG_X0 if self.word_size == 8 else UC_ARM_REG_R0

        for r_addr, resolver_func, addend in self.deferred_ifuncs:
            try:
                mu.reg_write(reg_arg0, hwcap)
                resolved_addr = self.emu.call_native(resolver_func)
                final_val = resolved_addr + addend
                self.write_val(r_addr, final_val)
                logger.debug("  [IFUNC] Resolved 0x%X -> 0x%X (at 0x%X)", resolver_func, final_val, r_addr)
            except Exception as e:
                logger.error("Failed to execute IFUNC resolver at 0x%X: %s", resolver_func, e)
                raise

    def write_val(self, addr: int, value: int) -> None:
        mask = (1 << (self.word_size * 8)) - 1
        data = (value & mask).to_bytes(self.word_size, 'little')
        self.emu.mu.mem_write(addr, data)

    def read_val(self, addr: int) -> int:
        return int.from_bytes(self.emu.mu.mem_read(addr, self.word_size), 'little')


class ARM32Relocator(BaseRelocator):
    word_size = 4

    def __init__(self, emu: 'Emulator', module: 'Module', resolver: 'SymbolResolver'):
        super().__init__(emu, module, resolver)

        self._handlers = {
            Relocation.TYPE.ARM_RELATIVE:    self._rel_relative,
            Relocation.TYPE.ARM_ABS32:       self._rel_abs32,
            Relocation.TYPE.ARM_GLOB_DAT:    self._rel_glob_dat,
            Relocation.TYPE.ARM_JUMP_SLOT:   self._rel_jump_slot,
            Relocation.TYPE.ARM_TLS_TPOFF32: self._rel_tls_tpoff,
            Relocation.TYPE.ARM_IRELATIVE:   self._rel_irelative,
        }

    def relocate_all(self, all_modules: List['Module']) -> None:
        reader = self.module._reader
        if not reader:
            return

        relocs = reader.relocations
        phase1_relative = []
        phase2_symbolic = []

        for rel in relocs:
            if rel.type in (Relocation.TYPE.ARM_RELATIVE, Relocation.TYPE.ARM_IRELATIVE):
                phase1_relative.append(rel)
            else:
                phase2_symbolic.append(rel)

        for rel in phase1_relative:
            r_addr = self.bias + rel.address
            handler = self._handlers.get(rel.type)
            if handler:
                handler(r_addr, rel, all_modules)

        # Symbolic & TLS
        for rel in phase2_symbolic:
            r_addr = self.bias + rel.address
            handler = self._handlers.get(rel.type)
            if handler:
                handler(r_addr, rel, all_modules)
            else:
                logger.warning("[ARM32Relocator] Unsupported relocation type: %s at 0x%X", rel.type, r_addr)

        # IFUNC
        self._resolve_deferred_ifuncs(hwcap=0x3FF)

    def _rel_relative(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        implicit_addend = self.read_val(r_addr)
        self.write_val(r_addr, self.bias + implicit_addend)

    def _rel_irelative(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        implicit_addend = self.read_val(r_addr)
        resolver_addr = self.bias + implicit_addend

        self.deferred_ifuncs.append((r_addr, resolver_addr, 0))

    def _rel_abs32(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        implicit_addend = self.read_val(r_addr)
        sym_name = rel.symbol.name if rel.has_symbol else ""
        res = self.resolver.resolve(sym_name, self.module, all_modules)

        if res.found:
            if res.is_ifunc:
                self.deferred_ifuncs.append((r_addr, res.address, implicit_addend))
            else:
                self.write_val(r_addr, res.address + implicit_addend)
        else:
            self.write_val(r_addr, implicit_addend)

    def _rel_glob_dat(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        sym_name = rel.symbol.name if rel.has_symbol else ""
        res = self.resolver.resolve(sym_name, self.module, all_modules)

        if res.found:
            if res.is_ifunc:
                self.deferred_ifuncs.append((r_addr, res.address, 0))
            else:
                self.write_val(r_addr, res.address)
        else:
            self.write_val(r_addr, 0)

    def _rel_jump_slot(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        self._rel_glob_dat(r_addr, rel, all_modules)

    def _rel_tls_tpoff(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        sym_name = rel.symbol.name if rel.has_symbol else ""
        res = self.resolver.resolve(sym_name, self.module, all_modules)
        tls_offset = res.tls_offset if res.found else getattr(self.module, 'tls_offset', 0)
        self.write_val(r_addr, tls_offset)

class ARM64Relocator(BaseRelocator):
    word_size = 8

    def __init__(self, emu: 'Emulator', module: 'Module', resolver: 'SymbolResolver'):
        super().__init__(emu, module, resolver)

        self._handlers = {
            Relocation.TYPE.AARCH64_RELATIVE:    self._rel_relative,
            Relocation.TYPE.AARCH64_ABS64:       self._rel_abs64,
            Relocation.TYPE.AARCH64_GLOB_DAT:    self._rel_glob_dat,
            Relocation.TYPE.AARCH64_JUMP_SLOT:   self._rel_jump_slot,
            Relocation.TYPE.AARCH64_TLS_TPREL64: self._rel_tls_tprel64,
            Relocation.TYPE.AARCH64_IRELATIVE:   self._rel_irelative,
        }

    def relocate_all(self, all_modules: List['Module']) -> None:
        reader = self.module._reader
        if not reader:
            return

        relocs = reader.relocations
        phase1_relative = []
        phase2_symbolic = []

        for rel in relocs:
            if rel.type in (Relocation.TYPE.AARCH64_RELATIVE, Relocation.TYPE.AARCH64_IRELATIVE):
                phase1_relative.append(rel)
            else:
                phase2_symbolic.append(rel)

        for rel in phase1_relative:
            r_addr = self.bias + rel.address
            handler = self._handlers.get(rel.type)
            if handler:
                handler(r_addr, rel, all_modules)

        # Symbolic & TLS
        for rel in phase2_symbolic:
            r_addr = self.bias + rel.address
            handler = self._handlers.get(rel.type)
            if handler:
                handler(r_addr, rel, all_modules)
            else:
                logger.warning("[ARM64Relocator] Unsupported relocation type: %s at 0x%X", rel.type, r_addr)

        # IFUNC
        self._resolve_deferred_ifuncs(hwcap=0xFF)

    def _rel_relative(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        self.write_val(r_addr, self.bias + rel.addend)

    def _rel_irelative(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        resolver_addr = self.bias + rel.addend
        self.deferred_ifuncs.append((r_addr, resolver_addr, 0))

    def _rel_abs64(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        sym_name = rel.symbol.name if rel.has_symbol else ""
        res = self.resolver.resolve(sym_name, self.module, all_modules)

        if res.found:
            if res.is_ifunc:
                self.deferred_ifuncs.append((r_addr, res.address, rel.addend))
            else:
                self.write_val(r_addr, res.address + rel.addend)
        else:
            self.write_val(r_addr, self.bias + rel.addend)

    def _rel_glob_dat(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        sym_name = rel.symbol.name if rel.has_symbol else ""
        res = self.resolver.resolve(sym_name, self.module, all_modules)

        if res.found:
            if res.is_ifunc:
                self.deferred_ifuncs.append((r_addr, res.address, rel.addend))
            else:
                self.write_val(r_addr, res.address + rel.addend)
        else:
            self.write_val(r_addr, self.bias + rel.addend)

    def _rel_jump_slot(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        self._rel_glob_dat(r_addr, rel, all_modules)

    def _rel_tls_tprel64(self, r_addr: int, rel: Relocation, all_modules: List['Module']) -> None:
        sym_name = rel.symbol.name if rel.has_symbol else ""
        res = self.resolver.resolve(sym_name, self.module, all_modules)
        
        sym_base = res.address if res.found else 0
        # TLS = sym + addend - TP
        val = sym_base + rel.addend - self.tp
        self.write_val(r_addr, val)