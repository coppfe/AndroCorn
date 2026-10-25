import struct
from typing import TYPE_CHECKING, Optional, List, Tuple, Any

# =========================================================================
# FUTURE DIRECT C-LEVEL OPTIMIZATION STUB
# =========================================================================
# import ctypes
# import unicorn.unicorn as _uc_module
# _uclib = getattr(_uc_module, 'uclib', None) or getattr(_uc_module, '_uc', None)
# if _uclib is None:
#     try:
#         from unicorn.unicorn_py3.unicorn import uclib as _uclib
#     except ImportError:
#         from unicorn.unicorn import _uc as _uclib

from unicorn.arm_const import *
from unicorn.arm64_const import *

from ..const import emu_const
from ..java.jni.reference import jobject

if TYPE_CHECKING:
    from unicorn import Uc
    from ..java.jvm.main import JavaVM


def _make_reg_64_property(reg_id: int):
    """Standard safe 32/64-bit register property descriptor."""
    def getter(self: "BaseRegistersMapping") -> int:
        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_reg_read is not None and self._uch is not None:
        #     self._fn_reg_read(self._uch, reg_id, self._reg_buf_64_ref)
        #     val = self._reg_buf_64.value
        #     return (val & 0xFFFFFFFF) if self._ptr_sz == 4 else val

        val = self._mu.reg_read(reg_id)
        return (val & 0xFFFFFFFF) if self._ptr_sz == 4 else val

    def setter(self: "BaseRegistersMapping", val: int) -> None:
        mask = 0xFFFFFFFF if self._ptr_sz == 4 else 0xFFFFFFFFFFFFFFFF
        masked_val = val & mask

        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_reg_write is not None and self._uch is not None:
        #     self._reg_buf_64.value = masked_val
        #     self._fn_reg_write(self._uch, reg_id, self._reg_buf_64_ref)
        #     return

        self._mu.reg_write(reg_id, masked_val)

    return property(getter, setter)


def _make_reg_128_property(reg_id: int):
    """Standard safe 128-bit NEON/Vector register property descriptor."""
    def getter(self: "BaseRegistersMapping") -> int:
        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_reg_read is not None and self._uch is not None:
        #     self._fn_reg_read(self._uch, reg_id, self._reg_buf_128_ref)
        #     return self._reg_buf_128[0] | (self._reg_buf_128[1] << 64)

        val = self._mu.reg_read(reg_id)
        if isinstance(val, (bytes, bytearray)):
            return int.from_bytes(val, 'little')
        return val

    def setter(self: "BaseRegistersMapping", val: int) -> None:
        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_reg_write is not None and self._uch is not None:
        #     self._reg_buf_128[0] = val & 0xFFFFFFFFFFFFFFFF
        #     self._reg_buf_128[1] = (val >> 64) & 0xFFFFFFFFFFFFFFFF
        #     self._fn_reg_write(self._uch, reg_id, self._reg_buf_128_ref)
        #     return

        self._mu.reg_write(reg_id, val)

    return property(getter, setter)


class BaseRegistersMapping:
    """Base class for register mapping and argument marshaling."""

    __slots__ = (
        "_arch", "_mu", "_uch", "_ptr_sz", "_fmt_ptr",
        # "_reg_buf_32", "_reg_buf_32_ref",
        # "_reg_buf_64", "_reg_buf_64_ref",
        # "_reg_buf_128", "_reg_buf_128_ref",
        # "_stack_raw_buf",
        # "_fn_reg_read", "_fn_reg_write", "_fn_mem_read", "_fn_mem_write",
        "pc", "sp", "lr", "tls", "flags", "ret", "syscall",
        "default", "float_arguments", "vector_arguments", "arguments",
        "_arg_reg_ids", "_syscall_arg_ids", "_fp_arg_ids", "_vector_arg_ids",
        "_name_to_id"
    )

    def __init__(self, mu: Optional["Uc"], arch: int, ptr_sz: int) -> None:
        self._arch = arch
        self._mu = mu
        self._ptr_sz = ptr_sz
        self._fmt_ptr = "<Q" if ptr_sz == 8 else "<I"

        # self._uch = mu._uch

        # --- Direct C-buffers initialization (archived) ---
        # if self._uch is not None and _uclib is not None:
        #     self._fn_reg_read = getattr(_uclib, 'uc_reg_read', None)
        #     self._fn_reg_write = getattr(_uclib, 'uc_reg_write', None)
        #     self._fn_mem_read = getattr(_uclib, 'uc_mem_read', None)
        #     self._fn_mem_write = getattr(_uclib, 'uc_mem_write', None)
        # else:
        #     self._fn_reg_read = None
        #     self._fn_reg_write = None
        #     self._fn_mem_read = None
        #     self._fn_mem_write = None
        #
        # self._reg_buf_32 = ctypes.c_uint32()
        # self._reg_buf_32_ref = ctypes.byref(self._reg_buf_32)
        # self._reg_buf_64 = ctypes.c_uint64()
        # self._reg_buf_64_ref = ctypes.byref(self._reg_buf_64)
        # self._reg_buf_128 = (ctypes.c_uint64 * 2)()
        # self._reg_buf_128_ref = ctypes.byref(self._reg_buf_128)
        # self._stack_raw_buf = (ctypes.c_char * 128)()

    def _read_reg_fast(self, reg_id: int) -> int:
        """Reads 32/64-bit register safely."""
        # if self._fn_reg_read is not None and self._uch is not None:
        #     self._fn_reg_read(self._uch, reg_id, self._reg_buf_64_ref)
        #     return self._reg_buf_64.value
        return self._mu.reg_read(reg_id)

    def _write_reg_fast(self, reg_id: int, val: int) -> None:
        """Writes 32/64-bit register safely."""
        # if self._fn_reg_write is not None and self._uch is not None:
        #     self._reg_buf_64.value = val & 0xFFFFFFFFFFFFFFFF
        #     self._fn_reg_write(self._uch, reg_id, self._reg_buf_64_ref)
        #     return
        self._mu.reg_write(reg_id, val & 0xFFFFFFFFFFFFFFFF)

    def _read_reg_128_fast(self, reg_id: int) -> int:
        """Reads 128-bit vector register safely."""
        # if self._fn_reg_read is not None and self._uch is not None:
        #     self._fn_reg_read(self._uch, reg_id, self._reg_buf_128_ref)
        #     return self._reg_buf_128[0] | (self._reg_buf_128[1] << 64)
        val = self._mu.reg_read(reg_id)
        if isinstance(val, (bytes, bytearray)):
            return int.from_bytes(val, 'little')
        return val

    def _write_reg_128_fast(self, reg_id: int, val: int) -> None:
        """Writes 128-bit vector register safely."""
        # if self._fn_reg_write is not None and self._uch is not None:
        #     self._reg_buf_128[0] = val & 0xFFFFFFFFFFFFFFFF
        #     self._reg_buf_128[1] = (val >> 64) & 0xFFFFFFFFFFFFFFFF
        #     self._fn_reg_write(self._uch, reg_id, self._reg_buf_128_ref)
        #     return
        self._mu.reg_write(reg_id, val)

    @staticmethod
    def _translate_val(java_vm: Optional["JavaVM"], val: Any) -> int:
        if isinstance(val, int):
            return val
        if val is None:
            return 0
        if java_vm is not None:
            if isinstance(val, (bytearray, bytes)):
                return java_vm.jni_env.add_local_reference(jobject(val))
            if hasattr(val, "jvm_id") or hasattr(type(val), "jvm_name") or hasattr(val, "jvm_name"):
                return java_vm.jni_env.add_local_reference(jobject(val))
        raise NotImplementedError(f"Cannot serialize argument of type {type(val)}: {val!r}")

    def read_syscall_args(self, count: int) -> Tuple[int, ...]:
        mask = 0xFFFFFFFF if self._ptr_sz == 4 else 0xFFFFFFFFFFFFFFFF
        reg_ids = self._syscall_arg_ids

        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_reg_read is not None and self._uch is not None:
        #     uch = self._uch
        #     buf = self._reg_buf_64
        #     buf_ref = self._reg_buf_64_ref
        #     res = []
        #     for i in range(count):
        #         self._fn_reg_read(uch, reg_ids[i], buf_ref)
        #         res.append(buf.value & mask)
        #     return tuple(res)

        return tuple(self._mu.reg_read(reg_ids[i]) & mask for i in range(count))

    def read_args(self, count: int) -> List[int]:
        arg_ids = self._arg_reg_ids
        max_regs = len(arg_ids)
        reg_count = min(count, max_regs)
        mask = 0xFFFFFFFF if self._ptr_sz == 4 else 0xFFFFFFFFFFFFFFFF

        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_reg_read is not None and self._uch is not None:
        #     uch = self._uch
        #     buf = self._reg_buf_32 if self._ptr_sz == 4 else self._reg_buf_64
        #     buf_ref = self._reg_buf_32_ref if self._ptr_sz == 4 else self._reg_buf_64_ref
        #     args = []
        #     for i in range(reg_count):
        #         buf.value = 0
        #         self._fn_reg_read(uch, arg_ids[i], buf_ref)
        #         args.append(buf.value & mask)
        # else:
        args = [self._mu.reg_read(arg_ids[i]) & mask for i in range(reg_count)]

        if count <= max_regs:
            return args

        sp = self.v_sp & mask
        stack_count = count - max_regs
        ptr_sz = self._ptr_sz
        stack_bytes = stack_count * ptr_sz

        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_mem_read is not None and self._uch is not None:
        #     raw_buf = self._stack_raw_buf if stack_bytes <= 128 else (ctypes.c_char * stack_bytes)()
        #     self._fn_mem_read(self._uch, sp, raw_buf, stack_bytes)
        #     fmt = f"<{stack_count}{'Q' if ptr_sz == 8 else 'I'}"
        #     args.extend(struct.unpack_from(fmt, raw_buf, 0))
        #     return args

        raw = bytes(self._mu.mem_read(sp, stack_bytes))
        fmt = f"<{stack_count}{'Q' if ptr_sz == 8 else 'I'}"
        args.extend(struct.unpack_from(fmt, raw, 0))

        return args

    def write_args(self, java_vm: Optional["JavaVM"], *argv: Any) -> None:
        arg_ids = self._arg_reg_ids
        max_regs = len(arg_ids)
        total_args = len(argv)
        reg_count = min(total_args, max_regs)
        translate = self._translate_val

        # --- Direct C-buffer fast path (archived) ---
        # if self._fn_reg_write is not None and self._uch is not None:
        #     uch = self._uch
        #     buf = self._reg_buf_64
        #     buf_ref = self._reg_buf_64_ref
        #     for i in range(reg_count):
        #         buf.value = translate(java_vm, argv[i]) & 0xFFFFFFFFFFFFFFFF
        #         self._fn_reg_write(uch, arg_ids[i], buf_ref)
        # else:
        for i in range(reg_count):
            self._mu.reg_write(arg_ids[i], translate(java_vm, argv[i]))

        if total_args > max_regs:
            stack_args = argv[max_regs:]
            stack_count = len(stack_args)

            sp_start = self.v_sp
            ptr_sz = self._ptr_sz
            sp_new = (sp_start - (ptr_sz * stack_count)) & ~0xF

            payload = bytearray(stack_count * ptr_sz)
            for i, arg in enumerate(stack_args):
                val = translate(java_vm, arg)
                payload[i * ptr_sz:(i + 1) * ptr_sz] = val.to_bytes(ptr_sz, "little")

            self._mu.mem_write(sp_new, bytes(payload))
            self.v_sp = sp_new

    def set_return_val(self, val: Any, high_val: Optional[int] = None) -> None:
        self.v_ret = val
        if high_val is not None:
            self.v_reg_1 = high_val


# =========================================================================
# ARM32 REGISTERS MAPPING
# =========================================================================

class RegistersMapping32(BaseRegistersMapping):
    v_reg_0  = _make_reg_64_property(UC_ARM_REG_R0)
    v_reg_1  = _make_reg_64_property(UC_ARM_REG_R1)
    v_reg_2  = _make_reg_64_property(UC_ARM_REG_R2)
    v_reg_3  = _make_reg_64_property(UC_ARM_REG_R3)
    v_reg_4  = _make_reg_64_property(UC_ARM_REG_R4)
    v_reg_5  = _make_reg_64_property(UC_ARM_REG_R5)
    v_reg_6  = _make_reg_64_property(UC_ARM_REG_R6)
    v_reg_7  = _make_reg_64_property(UC_ARM_REG_R7)
    v_reg_8  = _make_reg_64_property(UC_ARM_REG_R8)
    v_reg_9  = _make_reg_64_property(UC_ARM_REG_R9)
    v_reg_10 = _make_reg_64_property(UC_ARM_REG_R10)
    v_reg_11 = _make_reg_64_property(UC_ARM_REG_R11)
    v_reg_12 = _make_reg_64_property(UC_ARM_REG_R12)
    v_reg_13 = _make_reg_64_property(UC_ARM_REG_R13)
    v_reg_14 = _make_reg_64_property(UC_ARM_REG_R14)
    v_reg_15 = _make_reg_64_property(UC_ARM_REG_R15)

    v_reg_d_0 = _make_reg_64_property(UC_ARM_REG_D0)
    v_reg_d_1 = _make_reg_64_property(UC_ARM_REG_D1)
    v_reg_d_2 = _make_reg_64_property(UC_ARM_REG_D2)
    v_reg_d_3 = _make_reg_64_property(UC_ARM_REG_D3)
    v_reg_d_4 = _make_reg_64_property(UC_ARM_REG_D4)
    v_reg_d_5 = _make_reg_64_property(UC_ARM_REG_D5)
    v_reg_d_6 = _make_reg_64_property(UC_ARM_REG_D6)
    v_reg_d_7 = _make_reg_64_property(UC_ARM_REG_D7)

    v_reg_q_0 = _make_reg_128_property(UC_ARM_REG_Q0)
    v_reg_q_1 = _make_reg_128_property(UC_ARM_REG_Q1)
    v_reg_q_2 = _make_reg_128_property(UC_ARM_REG_Q2)
    v_reg_q_3 = _make_reg_128_property(UC_ARM_REG_Q3)
    v_reg_q_4 = _make_reg_128_property(UC_ARM_REG_Q4)
    v_reg_q_5 = _make_reg_128_property(UC_ARM_REG_Q5)
    v_reg_q_6 = _make_reg_128_property(UC_ARM_REG_Q6)
    v_reg_q_7 = _make_reg_128_property(UC_ARM_REG_Q7)

    v_pc      = _make_reg_64_property(UC_ARM_REG_PC)
    v_sp      = _make_reg_64_property(UC_ARM_REG_SP)
    v_lr      = _make_reg_64_property(UC_ARM_REG_LR)
    v_tls     = _make_reg_64_property(UC_ARM_REG_C13_C0_3)
    v_flags   = _make_reg_64_property(UC_ARM_REG_CPSR)
    v_ret     = _make_reg_64_property(UC_ARM_REG_R0)
    v_syscall = _make_reg_64_property(UC_ARM_REG_R7)

    FP_ARG_REG_IDS: Tuple[int, ...] = (
        UC_ARM_REG_D0, UC_ARM_REG_D1, UC_ARM_REG_D2, UC_ARM_REG_D3,
        UC_ARM_REG_D4, UC_ARM_REG_D5, UC_ARM_REG_D6, UC_ARM_REG_D7,
    )
    VECTOR_ARG_REG_IDS: Tuple[int, ...] = (
        UC_ARM_REG_Q0, UC_ARM_REG_Q1, UC_ARM_REG_Q2, UC_ARM_REG_Q3,
        UC_ARM_REG_Q4, UC_ARM_REG_Q5, UC_ARM_REG_Q6, UC_ARM_REG_Q7,
    )

    def __init__(self, mu: Optional["Uc"]) -> None:
        super().__init__(mu, emu_const.ARCH_ARM32, ptr_sz=4)

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

        self.reg_d_0 = UC_ARM_REG_D0
        self.reg_d_1 = UC_ARM_REG_D1
        self.reg_d_2 = UC_ARM_REG_D2
        self.reg_d_3 = UC_ARM_REG_D3
        self.reg_d_4 = UC_ARM_REG_D4
        self.reg_d_5 = UC_ARM_REG_D5
        self.reg_d_6 = UC_ARM_REG_D6
        self.reg_d_7 = UC_ARM_REG_D7

        self.reg_q_0 = UC_ARM_REG_Q0
        self.reg_q_1 = UC_ARM_REG_Q1
        self.reg_q_2 = UC_ARM_REG_Q2
        self.reg_q_3 = UC_ARM_REG_Q3
        self.reg_q_4 = UC_ARM_REG_Q4
        self.reg_q_5 = UC_ARM_REG_Q5
        self.reg_q_6 = UC_ARM_REG_Q6
        self.reg_q_7 = UC_ARM_REG_Q7

        self.pc      = UC_ARM_REG_PC
        self.sp      = UC_ARM_REG_SP
        self.lr      = UC_ARM_REG_LR
        self.tls     = UC_ARM_REG_C13_C0_3
        self.flags   = UC_ARM_REG_CPSR
        self.ret     = self.reg_0
        self.syscall = self.reg_7

        self.arguments = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        self.float_arguments = list(self.FP_ARG_REG_IDS)
        self.vector_arguments = list(self.VECTOR_ARG_REG_IDS)

        self._arg_reg_ids = tuple(self.arguments)
        self._syscall_arg_ids = (
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6
        )

        self.default = [
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
            UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
            UC_ARM_REG_R12, UC_ARM_REG_LR
        ]

        self._name_to_id = {f"reg_{i}": getattr(self, f"reg_{i}") for i in range(16)}
        self._name_to_id.update({
            "pc": self.pc, "sp": self.sp, "lr": self.lr,
            "tls": self.tls, "flags": self.flags, "ret": self.ret, "syscall": self.syscall
        })

    def is_thumb(self) -> bool:
        return (self.v_flags & (1 << 5)) != 0

    def set_thumb(self) -> None:
        self.v_flags |= (1 << 5)

    def clear_thumb(self) -> None:
        self.v_flags &= ~(1 << 5)

    def set_fp_return(self, bits: int, is_double: bool = False) -> None:
        self.v_reg_0 = bits & 0xFFFFFFFF
        if is_double:
            self.v_reg_1 = (bits >> 32) & 0xFFFFFFFF


# =========================================================================
# ARM64 REGISTERS MAPPING
# =========================================================================

class RegistersMapping64(BaseRegistersMapping):
    v_reg_0  = _make_reg_64_property(UC_ARM64_REG_X0)
    v_reg_1  = _make_reg_64_property(UC_ARM64_REG_X1)
    v_reg_2  = _make_reg_64_property(UC_ARM64_REG_X2)
    v_reg_3  = _make_reg_64_property(UC_ARM64_REG_X3)
    v_reg_4  = _make_reg_64_property(UC_ARM64_REG_X4)
    v_reg_5  = _make_reg_64_property(UC_ARM64_REG_X5)
    v_reg_6  = _make_reg_64_property(UC_ARM64_REG_X6)
    v_reg_7  = _make_reg_64_property(UC_ARM64_REG_X7)
    v_reg_8  = _make_reg_64_property(UC_ARM64_REG_X8)
    v_reg_9  = _make_reg_64_property(UC_ARM64_REG_X9)
    v_reg_10 = _make_reg_64_property(UC_ARM64_REG_X10)
    v_reg_11 = _make_reg_64_property(UC_ARM64_REG_X11)
    v_reg_12 = _make_reg_64_property(UC_ARM64_REG_X12)
    v_reg_13 = _make_reg_64_property(UC_ARM64_REG_X13)
    v_reg_14 = _make_reg_64_property(UC_ARM64_REG_X14)
    v_reg_15 = _make_reg_64_property(UC_ARM64_REG_X15)
    v_reg_16 = _make_reg_64_property(UC_ARM64_REG_X16)
    v_reg_17 = _make_reg_64_property(UC_ARM64_REG_X17)
    v_reg_18 = _make_reg_64_property(UC_ARM64_REG_X18)
    v_reg_19 = _make_reg_64_property(UC_ARM64_REG_X19)
    v_reg_20 = _make_reg_64_property(UC_ARM64_REG_X20)
    v_reg_21 = _make_reg_64_property(UC_ARM64_REG_X21)
    v_reg_22 = _make_reg_64_property(UC_ARM64_REG_X22)
    v_reg_23 = _make_reg_64_property(UC_ARM64_REG_X23)
    v_reg_24 = _make_reg_64_property(UC_ARM64_REG_X24)
    v_reg_25 = _make_reg_64_property(UC_ARM64_REG_X25)
    v_reg_26 = _make_reg_64_property(UC_ARM64_REG_X26)
    v_reg_27 = _make_reg_64_property(UC_ARM64_REG_X27)
    v_reg_28 = _make_reg_64_property(UC_ARM64_REG_X28)
    v_reg_29 = _make_reg_64_property(UC_ARM64_REG_X29)
    v_reg_30 = _make_reg_64_property(UC_ARM64_REG_X30)

    v_reg_d_0 = _make_reg_64_property(UC_ARM64_REG_D0)
    v_reg_d_1 = _make_reg_64_property(UC_ARM64_REG_D1)
    v_reg_d_2 = _make_reg_64_property(UC_ARM64_REG_D2)
    v_reg_d_3 = _make_reg_64_property(UC_ARM64_REG_D3)
    v_reg_d_4 = _make_reg_64_property(UC_ARM64_REG_D4)
    v_reg_d_5 = _make_reg_64_property(UC_ARM64_REG_D5)
    v_reg_d_6 = _make_reg_64_property(UC_ARM64_REG_D6)
    v_reg_d_7 = _make_reg_64_property(UC_ARM64_REG_D7)

    v_reg_q_0 = _make_reg_128_property(UC_ARM64_REG_Q0)
    v_reg_q_1 = _make_reg_128_property(UC_ARM64_REG_Q1)
    v_reg_q_2 = _make_reg_128_property(UC_ARM64_REG_Q2)
    v_reg_q_3 = _make_reg_128_property(UC_ARM64_REG_Q3)
    v_reg_q_4 = _make_reg_128_property(UC_ARM64_REG_Q4)
    v_reg_q_5 = _make_reg_128_property(UC_ARM64_REG_Q5)
    v_reg_q_6 = _make_reg_128_property(UC_ARM64_REG_Q6)
    v_reg_q_7 = _make_reg_128_property(UC_ARM64_REG_Q7)

    v_pc      = _make_reg_64_property(UC_ARM64_REG_PC)
    v_sp      = _make_reg_64_property(UC_ARM64_REG_SP)
    v_lr      = _make_reg_64_property(UC_ARM64_REG_X30)
    v_tls     = _make_reg_64_property(UC_ARM64_REG_TPIDR_EL0)
    v_flags   = _make_reg_64_property(UC_ARM64_REG_NZCV)
    v_ret     = _make_reg_64_property(UC_ARM64_REG_X0)
    v_syscall = _make_reg_64_property(UC_ARM64_REG_X8)

    FP_ARG_REG_IDS: Tuple[int, ...] = (
        UC_ARM64_REG_D0, UC_ARM64_REG_D1, UC_ARM64_REG_D2, UC_ARM64_REG_D3,
        UC_ARM64_REG_D4, UC_ARM64_REG_D5, UC_ARM64_REG_D6, UC_ARM64_REG_D7,
    )
    VECTOR_ARG_REG_IDS: Tuple[int, ...] = (
        UC_ARM64_REG_Q0, UC_ARM64_REG_Q1, UC_ARM64_REG_Q2, UC_ARM64_REG_Q3,
        UC_ARM64_REG_Q4, UC_ARM64_REG_Q5, UC_ARM64_REG_Q6, UC_ARM64_REG_Q7,
    )

    def __init__(self, mu: Optional["Uc"]) -> None:
        super().__init__(mu, emu_const.ARCH_ARM64, ptr_sz=8)

        self.reg_0  = UC_ARM64_REG_X0
        self.reg_1  = UC_ARM64_REG_X1
        self.reg_2  = UC_ARM64_REG_X2
        self.reg_3  = UC_ARM64_REG_X3
        self.reg_4  = UC_ARM64_REG_X4
        self.reg_5  = UC_ARM64_REG_X5
        self.reg_6  = UC_ARM64_REG_X6
        self.reg_7  = UC_ARM64_REG_X7
        self.reg_8  = UC_ARM64_REG_X8
        self.reg_9  = UC_ARM64_REG_X9
        self.reg_10 = UC_ARM64_REG_X10
        self.reg_11 = UC_ARM64_REG_X11
        self.reg_12 = UC_ARM64_REG_X12
        self.reg_13 = UC_ARM64_REG_X13
        self.reg_14 = UC_ARM64_REG_X14
        self.reg_15 = UC_ARM64_REG_X15
        self.reg_16 = UC_ARM64_REG_X16
        self.reg_17 = UC_ARM64_REG_X17
        self.reg_18 = UC_ARM64_REG_X18
        self.reg_19 = UC_ARM64_REG_X19
        self.reg_20 = UC_ARM64_REG_X20
        self.reg_21 = UC_ARM64_REG_X21
        self.reg_22 = UC_ARM64_REG_X22
        self.reg_23 = UC_ARM64_REG_X23
        self.reg_24 = UC_ARM64_REG_X24
        self.reg_25 = UC_ARM64_REG_X25
        self.reg_26 = UC_ARM64_REG_X26
        self.reg_27 = UC_ARM64_REG_X27
        self.reg_28 = UC_ARM64_REG_X28
        self.reg_29 = UC_ARM64_REG_X29
        self.reg_30 = UC_ARM64_REG_X30

        self.reg_d_0 = UC_ARM64_REG_D0
        self.reg_d_1 = UC_ARM64_REG_D1
        self.reg_d_2 = UC_ARM64_REG_D2
        self.reg_d_3 = UC_ARM64_REG_D3
        self.reg_d_4 = UC_ARM64_REG_D4
        self.reg_d_5 = UC_ARM64_REG_D5
        self.reg_d_6 = UC_ARM64_REG_D6
        self.reg_d_7 = UC_ARM64_REG_D7

        self.reg_q_0 = UC_ARM64_REG_Q0
        self.reg_q_1 = UC_ARM64_REG_Q1
        self.reg_q_2 = UC_ARM64_REG_Q2
        self.reg_q_3 = UC_ARM64_REG_Q3
        self.reg_q_4 = UC_ARM64_REG_Q4
        self.reg_q_5 = UC_ARM64_REG_Q5
        self.reg_q_6 = UC_ARM64_REG_Q6
        self.reg_q_7 = UC_ARM64_REG_Q7

        self.pc      = UC_ARM64_REG_PC
        self.sp      = UC_ARM64_REG_SP
        self.lr      = UC_ARM64_REG_X30
        self.tls     = UC_ARM64_REG_TPIDR_EL0
        self.flags   = UC_ARM64_REG_NZCV
        self.ret     = self.reg_0
        self.syscall = self.reg_8

        self.arguments = [
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7
        ]
        self.float_arguments = list(self.FP_ARG_REG_IDS)
        self.vector_arguments = list(self.VECTOR_ARG_REG_IDS)

        self._arg_reg_ids = tuple(self.arguments)
        self._syscall_arg_ids = self._arg_reg_ids

        self.default = [getattr(self, f"reg_{i}") for i in range(31)]

        self._name_to_id = {f"reg_{i}": getattr(self, f"reg_{i}") for i in range(31)}
        self._name_to_id.update({
            "pc": self.pc, "sp": self.sp, "lr": self.lr,
            "tls": self.tls, "flags": self.flags, "ret": self.ret, "syscall": self.syscall
        })

    def is_thumb(self) -> bool:
        return False

    def set_thumb(self) -> None:
        raise NotImplementedError("Thumb mode is only supported on ARM32")

    def clear_thumb(self) -> None:
        raise NotImplementedError("Thumb mode is only supported on ARM32")

    def set_fp_return(self, bits: int, is_double: bool = False) -> None:
        self.v_reg_d_0 = bits & (0xFFFFFFFFFFFFFFFF if is_double else 0xFFFFFFFF)


if TYPE_CHECKING:
    class RegistersMapping(RegistersMapping64): pass
else:
    class RegistersMapping:
        def __new__(cls, mu: Optional["Uc"], arch: int):
            if arch == emu_const.ARCH_ARM64:
                return RegistersMapping64(mu)
            elif arch == emu_const.ARCH_ARM32:
                return RegistersMapping32(mu)
            raise ValueError(f"Wrong arch identifier: {arch}. Expected 1 (ARM32) or 2 (ARM64)")