import struct
from typing import TYPE_CHECKING, Optional, List, Tuple, Any
from unicorn.arm_const import *
from unicorn.arm64_const import *

from ..const import emu_const
from ..java.jni.reference import jobject

if TYPE_CHECKING:
    from unicorn import Uc
    from ..java.jvm.main import JavaVM


class RegistersMapping:
    if TYPE_CHECKING:
        v_reg_0: int;  v_reg_1: int;  v_reg_2: int;  v_reg_3: int
        v_reg_4: int;  v_reg_5: int;  v_reg_6: int;  v_reg_7: int
        v_reg_8: int;  v_reg_9: int;  v_reg_10: int; v_reg_11: int
        v_reg_12: int; v_reg_13: int; v_reg_14: int; v_reg_15: int
        v_reg_16: int; v_reg_17: int; v_reg_18: int; v_reg_19: int
        v_reg_20: int; v_reg_21: int; v_reg_22: int; v_reg_23: int
        v_reg_24: int; v_reg_25: int; v_reg_26: int; v_reg_27: int
        v_reg_28: int; v_reg_29: int; v_reg_30: int

        v_pc: int
        v_sp: int
        v_lr: int
        v_tls: int
        v_flags: int
        v_ret: int
        v_syscall: int

    def __init__(self, mu: Optional['Uc'], arch: int) -> None:
        self._arch = arch
        self._mu = mu
        self._ptr_sz = 8 if arch == emu_const.ARCH_ARM64 else 4
        self._fmt_ptr = "<Q" if arch == emu_const.ARCH_ARM64 else "<I"

        self._name_to_id = {}

        if arch == emu_const.ARCH_ARM32:
            self.reg_0   = UC_ARM_REG_R0
            self.reg_1   = UC_ARM_REG_R1
            self.reg_2   = UC_ARM_REG_R2
            self.reg_3   = UC_ARM_REG_R3
            self.reg_4   = UC_ARM_REG_R4
            self.reg_5   = UC_ARM_REG_R5
            self.reg_6   = UC_ARM_REG_R6
            self.reg_7   = UC_ARM_REG_R7
            self.reg_8   = UC_ARM_REG_R8
            self.reg_9   = UC_ARM_REG_R9
            self.reg_10  = UC_ARM_REG_R10
            self.reg_11  = UC_ARM_REG_R11
            self.reg_12  = UC_ARM_REG_R12
            self.reg_13  = UC_ARM_REG_R13
            self.reg_14  = UC_ARM_REG_R14
            self.reg_15  = UC_ARM_REG_R15

            self.pc      = UC_ARM_REG_PC
            self.sp      = UC_ARM_REG_SP
            self.lr      = UC_ARM_REG_LR
            self.tls     = UC_ARM_REG_C13_C0_3
            self.flags   = UC_ARM_REG_CPSR

            self.default = [
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                UC_ARM_REG_R12, UC_ARM_REG_LR
            ]
            self.arguments = [
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
            ]
            self.ret     = self.reg_0
            self.syscall = self.reg_7

            for i in range(16):
                self._name_to_id[f"reg_{i}"] = getattr(self, f"reg_{i}")

            self._name_to_id["pc"] = self.pc
            self._name_to_id["sp"] = self.sp
            self._name_to_id["lr"] = self.lr
            self._name_to_id["tls"] = self.tls
            self._name_to_id["flags"] = self.flags
            self._name_to_id["ret"] = self.ret
            self._name_to_id["syscall"] = self.syscall

        elif arch == emu_const.ARCH_ARM64:
            self.reg_0   = UC_ARM64_REG_X0
            self.reg_1   = UC_ARM64_REG_X1
            self.reg_2   = UC_ARM64_REG_X2
            self.reg_3   = UC_ARM64_REG_X3
            self.reg_4   = UC_ARM64_REG_X4
            self.reg_5   = UC_ARM64_REG_X5
            self.reg_6   = UC_ARM64_REG_X6
            self.reg_7   = UC_ARM64_REG_X7
            self.reg_8   = UC_ARM64_REG_X8
            self.reg_9   = UC_ARM64_REG_X9
            self.reg_10  = UC_ARM64_REG_X10
            self.reg_11  = UC_ARM64_REG_X11
            self.reg_12  = UC_ARM64_REG_X12
            self.reg_13  = UC_ARM64_REG_X13
            self.reg_14  = UC_ARM64_REG_X14
            self.reg_15  = UC_ARM64_REG_X15
            self.reg_16  = UC_ARM64_REG_X16
            self.reg_17  = UC_ARM64_REG_X17
            self.reg_18  = UC_ARM64_REG_X18
            self.reg_19  = UC_ARM64_REG_X19
            self.reg_20  = UC_ARM64_REG_X20
            self.reg_21  = UC_ARM64_REG_X21
            self.reg_22  = UC_ARM64_REG_X22
            self.reg_23  = UC_ARM64_REG_X23
            self.reg_24  = UC_ARM64_REG_X24
            self.reg_25  = UC_ARM64_REG_X25
            self.reg_26  = UC_ARM64_REG_X26
            self.reg_27  = UC_ARM64_REG_X27
            self.reg_28  = UC_ARM64_REG_X28
            self.reg_29  = UC_ARM64_REG_X29
            self.reg_30  = UC_ARM64_REG_X30

            self.pc      = UC_ARM64_REG_PC
            self.sp      = UC_ARM64_REG_SP
            self.lr      = UC_ARM64_REG_X30
            self.tls     = UC_ARM64_REG_TPIDR_EL0
            self.flags   = UC_ARM64_REG_NZCV

            self.default = [
                UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,
                UC_ARM64_REG_X4,  UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,
                UC_ARM64_REG_X8,  UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11,
                UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
                UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
                UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
                UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
                UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30
            ]
            self.arguments = [
                UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7
            ]
            self.ret     = self.reg_0
            self.syscall = self.reg_8

            for i in range(31):
                self._name_to_id[f"reg_{i}"] = getattr(self, f"reg_{i}")

            self._name_to_id["pc"] = self.pc
            self._name_to_id["sp"] = self.sp
            self._name_to_id["lr"] = self.lr
            self._name_to_id["tls"] = self.tls
            self._name_to_id["flags"] = self.flags
            self._name_to_id["ret"] = self.ret
            self._name_to_id["syscall"] = self.syscall
        else:
            raise RuntimeError("Wrong arch identifier. Expected 1 (ARM32) or 2 (ARM64)")

    def set_mu(self, mu: 'Uc') -> None:
        self._mu = mu

    def __getattr__(self, name: str):
        if name.startswith("v_"):
            lookup = name[2:].lower()
            if "_name_to_id" in self.__dict__ and lookup in self._name_to_id:
                if self._mu is None:
                    raise RuntimeError("Unicorn instance (_mu) is not set in RegistersMapping!")
                return self._mu.reg_read(self._name_to_id[lookup])
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def __setattr__(self, name: str, value):
        if name.startswith("v_"):
            lookup = name[2:].lower()
            if "_name_to_id" in self.__dict__ and lookup in self._name_to_id:
                if self._mu is None:
                    raise RuntimeError("Unicorn instance (_mu) is not set in RegistersMapping!")
                self._mu.reg_write(self._name_to_id[lookup], value)
                return
            raise AttributeError(f"Unknown virtual register attribute: '{name}'")
        super().__setattr__(name, value)

    def is_thumb(self) -> bool:
        if self._arch != emu_const.ARCH_ARM32:
            return False
        return (self.v_flags & (1 << 5)) != 0

    def set_thumb(self) -> None:
        assert self._arch == emu_const.ARCH_ARM32, "Thumb mode is only supported on ARM32"
        self.v_flags = self.v_flags | (1 << 5)

    def clear_thumb(self) -> None:
        assert self._arch == emu_const.ARCH_ARM32, "Thumb mode is only supported on ARM32"
        self.v_flags = self.v_flags & ~(1 << 5)

    @staticmethod
    def _translate_val(java_vm: Optional['JavaVM'], val: Any) -> int:
        if isinstance(val, int):
            return val
        if val is None:
            return 0
        if java_vm is not None:
            if isinstance(val, (bytearray, bytes)):
                return java_vm.jni_env.add_local_reference(jobject(val))
            if hasattr(val, 'jvm_id') or hasattr(type(val), 'jvm_name') or hasattr(val, 'jvm_name'):
                return java_vm.jni_env.add_local_reference(jobject(val))
        raise NotImplementedError(f"Cannot serialize argument of type {type(val)}: {val!r}")

    def read_syscall_args(self, count: int) -> Tuple[int, ...]:
        """Reads arguments for system calls directly from registers."""
        return tuple(getattr(self, f"v_reg_{i}") for i in range(count))

    def read_args(self, count: int) -> List[int]:
        """
        Reads function call arguments according to the architecture's calling convention:
        first from registers (arguments), then falls back to reading the stack.
        """
        if self._mu is None:
            raise RuntimeError("Unicorn instance is not set!")

        max_regs = len(self.arguments)
        reg_count = min(count, max_regs)
        args = [getattr(self, f"v_reg_{i}") for i in range(reg_count)]

        if count <= max_regs:
            return args

        stack_count = count - max_regs
        total_bytes = stack_count * self._ptr_sz
        stack_raw = self._mu.mem_read(self.v_sp, total_bytes)

        fmt = f"<{stack_count}{'Q' if self._ptr_sz == 8 else 'I'}"
        args.extend(struct.unpack(fmt, stack_raw))
        return args

    def write_args(self, java_vm: Optional['JavaVM'], *argv: Any) -> None:
        """
        Writes function call arguments according to the architecture's calling convention:
        first into argument registers, then remaining onto the stack (aligned to 16 bytes).
        """
        if self._mu is None:
            raise RuntimeError("Unicorn instance is not set!")

        max_regs = len(self.arguments)
        total_args = len(argv)

        reg_count = min(total_args, max_regs)
        for i in range(reg_count):
            setattr(self, f"v_reg_{i}", self._translate_val(java_vm, argv[i]))

        if total_args > max_regs:
            stack_args = argv[max_regs:]
            stack_count = len(stack_args)

            sp_start = self.v_sp
            sp_new = (sp_start - (self._ptr_sz * stack_count)) & ~0xF

            payload = b"".join(
                struct.pack(self._fmt_ptr, self._translate_val(java_vm, arg))
                for arg in stack_args
            )

            self._mu.mem_write(sp_new, payload)
            self.v_sp = sp_new

    def set_return_val(self, val: Any, high_val: Optional[int] = None) -> None:
        """Sets return value in v_ret (and v_reg_1 if 64-bit pair on 32-bit)."""
        self.v_ret = val
        if high_val is not None:
            self.v_reg_1 = high_val