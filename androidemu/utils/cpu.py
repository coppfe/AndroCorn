import struct

from ..data.mem_map import ASM_CODE, PAGE_SIZE

from unicorn.arm64_const import *
from unicorn.arm_const import *

from unicorn import UC_ARCH_ARM64

from ..const.registers import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc
    from ..emulator import Emulator

class CPU_Utils:

    TYPE_MRC = 0   # 32-bit
    TYPE_MRRC = 1  # 64-bit

    MRS_BASE_64 = 0xD5300000 # move from system register
    MSR_BASE_64 = 0xD5100000  # move to system register
    
    MRC_BASE_32  = 0xEE100F10 # move from coprocessor
    MCR_BASE_32  = 0xEE000F10 # move to coprocessor

    MRRC_BASE_32 = 0xEC500F00 # move from coprocessor register
    MCRR_BASE_32 = 0xEC400F00 # move to coprocessor register

    # ID : (Op0, Op1, CRn, CRm, Op2)
    REGS_64 = {
        ARM64_CNTVCT_EL0: (3, 3, 14, 0, 2),
        ARM64_CNTFRQ_EL0: (3, 3, 14, 0, 0),
        ARM64_CNTKCTL_EL1: (3, 0, 14, 1, 0),
    }

    # ID : (is_64bit_reg, coproc, opc1, opc2, CRn, CRm)
    REGS_32 = {
        ARM32_CNTVCT: (True,  15, 1, 0, 0, 14), # CNTVCT (MRRC)
        ARM32_CNTFRQ: (False, 15, 0, 0, 14, 0), # CNTFRQ (MRC)
        ARM32_CNTKCTL: (False, 15, 0, 0, 14, 1), # CNTKCTL (MRC)
    }

    def __init__(self, emu: 'Emulator'):
        self.mu: 'Uc' = emu.mu
        pass

    def _enable_vfp32(self):
        # MRC p15, #0, r1, c1, c0, #2
        # ORR r1, r1, #(0xf << 20)
        # MCR p15, #0, r1, c1, c0, #2
        # MOV r1, #0
        # MCR p15, #0, r1, c7, c5, #4
        # MOV r0,#0x40000000
        # FMXR FPEXC, r0
        code = '11EE501F'
        code += '41F47001'
        code += '01EE501F'
        code += '4FF00001'
        code += '07EE951F'
        code += '4FF08040'
        code += 'E8EE100A'
        # vpush {d8}
        code += '2ded028b'

        address = ASM_CODE
        mem_size = PAGE_SIZE
        code_bytes = bytes.fromhex(code)

        try:
            self.mu.mem_write(address, code_bytes)
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)
            
            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_write(address, b'\x00' * len(code_bytes))
        
    #arm64
    '''
    mrs    x1, cpacr_el1
    mov    x0, #(3 << 20)
    orr    x0, x1, x0
    msr    cpacr_el1, x0
    '''
    def _enable_vfp64(self):
        #arm64 enable vfp
        x = 0
        x = self.mu.reg_read(UC_ARM64_REG_CPACR_EL1)
        x |= 0x300000; # set FPEN bit
        self.mu.reg_write(UC_ARM64_REG_CPACR_EL1, x)

    def __encode_64(self, reg_id, is_write: bool):
        params = self.REGS_64.get(reg_id)
        if not params: raise ValueError(f"Unknown ARM64 reg: {hex(reg_id)}")
        
        op0, op1, crn, crm, op2 = params
        insn = self.MSR_BASE_64 if is_write else self.MRS_BASE_64
        
        insn |= (op0 << 19)
        insn |= (op1 << 16)
        insn |= (crn << 12)
        insn |= (crm << 8)
        insn |= (op2 << 5)
        insn |= 0 # Rt = X0
        return struct.pack('<I', insn), True

    def __encode_32(self, reg_id, is_write: bool):
        params = self.REGS_32.get(reg_id)
        if not params: raise ValueError(f"Unknown ARM32 reg: {hex(reg_id)}")
        
        is_64bit_reg, coproc, op1, op2, crn, crm = params

        if is_64bit_reg:
            # MCRR / MRRC (64-bit)
            insn = self.MCRR_BASE_32 if is_write else self.MRRC_BASE_32
            insn |= (coproc << 8)
            insn |= (op1 << 4)
            insn |= crm
            # Rt=R0, Rt2=R1
            return struct.pack('<I', insn), True
        else:
            # MCR / MRC (32-bit)
            insn = self.MCR_BASE_32 if is_write else self.MRC_BASE_32
            insn |= (op1 << 21)
            insn |= (crn << 16)
            insn |= (coproc << 8)
            insn |= (op2 << 5)
            insn |= crm
            # Rt=R0
            return struct.pack('<I', insn), False
        
    def __emulate(self, code_bytes: bytes, is_64: bool):
        address = ASM_CODE
        try:
            self.mu.mem_write(address, code_bytes)
            
            stop_addr = address + 0x10 
            self.mu.reg_write(UC_ARM64_REG_X30 if is_64 else UC_ARM_REG_LR, stop_addr)

            self.mu.emu_start(address, address + 4, count=1)
        finally:
            self.mu.mem_write(address, b'\x00' * len(code_bytes))

    def _read_sys_reg(self, register_id: int):
        is_64 = self.mu._arch == UC_ARCH_ARM64
        code_bytes, is_res_64 = self.__encode_64(register_id, False) if is_64 else \
                                self.__encode_32(register_id, False)

        self.__emulate(code_bytes, is_64)

        if is_64:
            return self.mu.reg_read(UC_ARM64_REG_X0)
        
        res_low = self.mu.reg_read(UC_ARM_REG_R0)
        if is_res_64:
            res_high = self.mu.reg_read(UC_ARM_REG_R1)
            return (res_high << 32) | res_low
        return res_low

    def _write_sys_reg(self, register_id: int, value: int):
        is_64 = self.mu._arch == UC_ARCH_ARM64
        code_bytes, is_val_64 = self.__encode_64(register_id, True) if is_64 else \
                                self.__encode_32(register_id, True)

        if is_64:
            self.mu.reg_write(UC_ARM64_REG_X0, value)
        else:
            self.mu.reg_write(UC_ARM_REG_R0, value & 0xFFFFFFFF)
            if is_val_64:
                self.mu.reg_write(UC_ARM_REG_R1, value >> 32)

        self.__emulate(code_bytes, is_64)