import logging

from typing import TYPE_CHECKING

from lief.ELF import Relocation

from unicorn.arm_const import *
from unicorn.arm64_const import *


if TYPE_CHECKING:
    from ..emulator import Emulator

R_ARM_ABS32 = Relocation.TYPE.ARM_ABS32
R_ARM_GLOB_DAT = Relocation.TYPE.ARM_GLOB_DAT
R_ARM_JUMP_SLOT = Relocation.TYPE.ARM_JUMP_SLOT
R_ARM_RELATIVE = Relocation.TYPE.ARM_RELATIVE
R_ARM_IRELATIVE = Relocation.TYPE.ARM_IRELATIVE
R_ARM_TLS_DTPOFF32 = Relocation.TYPE.ARM_TLS_DTPOFF32
R_ARM_TLS_TPOFF32 = Relocation.TYPE.ARM_TLS_TPOFF32

R_AARCH64_ABS64 = Relocation.TYPE.AARCH64_ABS64
R_AARCH64_COPY = Relocation.TYPE.AARCH64_COPY
R_AARCH64_GLOB_DAT = Relocation.TYPE.AARCH64_GLOB_DAT
R_AARCH64_JUMP_SLOT = Relocation.TYPE.AARCH64_JUMP_SLOT
R_AARCH64_RELATIVE = Relocation.TYPE.AARCH64_RELATIVE
R_AARCH64_TLS_TPREL64 = Relocation.TYPE.AARCH64_TLS_DTPREL64
R_AARCH64_IRELATIVE = Relocation.TYPE.AARCH64_IRELATIVE

logger = logging.getLogger(__name__)

class Relocator:
    def __init__(self, emu: 'Emulator', load_bias):
        self.emu = emu
        self.load_bias = load_bias
        self.word_size = emu.get_ptr_size()

    def write_val(self, addr, value):        
        try:
            mask = (1 << (self.word_size * 8)) - 1
            data = (value & mask).to_bytes(self.word_size, 'little')
            self.emu.mu.mem_write(addr, data)
        except Exception as e:
            logger.error(f"[Relocator] Write fault at {hex(addr)}: {e}")

    def read_val(self, addr):
        return int.from_bytes(self.emu.mu.mem_read(addr, self.word_size), 'little')

class ARM32Relocator(Relocator):
    def apply(self, r_type, r_addr, sym_addr, sym_name, addend, tls_info=None):
        implicit = self.read_val(r_addr)

        new_val = None

        # 1. Hooks
        if sym_name in self.emu.linker.symbol_hooks:
            hook_addr = self.emu.linker.symbol_hooks[sym_name]
            self.write_val(r_addr, hook_addr)
            return

        # 2. R_ARM_RELATIVE (B + A)
        if r_type == R_ARM_RELATIVE:
            new_val = self.load_bias + implicit
            self.write_val(r_addr, new_val)

        # 3. SYM RELOC (S + A)
        elif r_type in (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT):
            if sym_addr:
                self.write_val(r_addr, sym_addr)
            else:
                self.write_val(r_addr, 0)

        # 2. ABS32 (implicit) (S + A)
        elif r_type == R_ARM_ABS32:
            if sym_addr:
                self.write_val(r_addr, sym_addr + implicit)
            else:
                self.write_val(r_addr, implicit)

        # 4. IRELATIVE
        elif r_type == R_ARM_IRELATIVE:
            resolver_addr = self.load_bias + implicit
            self.emu.mu.reg_write(UC_ARM_REG_R0, 0x3FF) # HWCAP
            new_val = self.emu.call_native(resolver_addr)
            self.write_val(r_addr, new_val)
        
        else:
            logger.warning(f"[ARM32Relocator] Unsupported relocation type: {r_type}")

class ARM64Relocator(Relocator):
    def apply(self, r_type, r_addr, sym_addr, sym_name, addend, tls_info=None):
        if sym_name in self.emu.linker.symbol_hooks:
            hook_addr = self.emu.linker.symbol_hooks[sym_name]
            self.write_val(r_addr, hook_addr)
            return

        # 2. RELATIVE: B + A
        if r_type == R_AARCH64_RELATIVE:
            val = self.load_bias + addend
            self.write_val(r_addr, val)

        # 3. ABS64 / GLOB_DAT / JUMP_SLOT: S + A
        elif r_type in (R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
            if sym_addr:
                val = sym_addr + addend
            else:
                val = self.load_bias + addend
            self.write_val(r_addr, val)

        # 4. IRELATIVE: B + A -> call IFUNC resolver
        elif r_type == R_AARCH64_IRELATIVE:
            resolver_addr = self.load_bias + addend
            self.emu.mu.reg_write(UC_ARM64_REG_X0, 0xFF) # HWCAP
            result = self.emu.call_native(resolver_addr)
            self.write_val(r_addr, result)

        # 5. TLS (TPREL64)
        elif r_type == R_AARCH64_TLS_TPREL64:
            offset = tls_info['offset'] if tls_info else 0
            # S + A + TP_OFFSET
            val = (sym_addr if sym_addr else 0) + addend + offset
            self.write_val(r_addr, val)
            
        else:
            logger.warning(f"[ARM64Relocator] Unsupported relocation type: {r_type}")