import struct
from typing import TYPE_CHECKING, List, Tuple

from ...java.jvm.constants import JAVA_NULL
from ...java.signature import ArgKind

if TYPE_CHECKING:
    from ...core.registers import RegistersMapping
    from ...java.jni.main import JNIEnv
    from ...utils.memory.map import MemoryMap

# =========================================================================
# CONSTANTS & COMPILED STRUCTS
# =========================================================================

# Kinds that occupy 64-bit (2 words) in ARM32 registers / va_list
_WIDE_OR_FP_KINDS = (ArgKind.LONG, ArgKind.FLOAT, ArgKind.DOUBLE)

# Size of one jvalue union slot on both 32-bit and 64-bit architectures
_JVALUE_SLOT_SIZE = 8

# Pre-compiled unpackers for jvalue[]
_JVALUE_STRUCTS = {
    ArgKind.BOOLEAN: struct.Struct("<B"),
    ArgKind.BYTE:    struct.Struct("<b"),
    ArgKind.CHAR:    struct.Struct("<H"),
    ArgKind.SHORT:   struct.Struct("<h"),
    ArgKind.INT:     struct.Struct("<i"),
    ArgKind.LONG:    struct.Struct("<q"),
    ArgKind.FLOAT:   struct.Struct("<f"),
    ArgKind.DOUBLE:  struct.Struct("<d"),
}

_STRUCT_PTR32 = struct.Struct("<I")
_STRUCT_PTR64 = struct.Struct("<Q")
_STRUCT_VA_LIST64 = struct.Struct("<QQQii")  # stk, gr_top, vr_top, gr_offs, vr_offs


# =========================================================================
# INTERNAL HELPERS
# =========================================================================

def _double_from_bits(bits: int) -> float:
    """Reinterprets a 64-bit integer bitfield as an IEEE-754 double."""
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


def _unpack_int(kind: ArgKind, raw: int) -> int:
    """
    Converts raw register bits into a Java-compliant primitive value:
      - boolean: 0 or 1
      - char: unsigned 16-bit
      - byte / short / int: signed two's complement
    """
    if kind == ArgKind.BOOLEAN:
        return 1 if (raw & 0xFF) else 0
    if kind == ArgKind.CHAR:
        return raw & 0xFFFF
    if kind == ArgKind.BYTE:
        return ((raw + 0x80) & 0xFF) - 0x80
    if kind == ArgKind.SHORT:
        return ((raw + 0x8000) & 0xFFFF) - 0x8000
    # ArgKind.INT
    return ((raw + 0x80000000) & 0xFFFFFFFF) - 0x80000000


# =========================================================================
# 1. VARIADIC REGISTER CALLS (Call<T>Method)
# =========================================================================

def count_arg_words32(args_kinds: Tuple[ArgKind, ...], first_reg: int = 3) -> int:
    """
    Counts how many 32-bit register/stack words the arguments occupy on ARM32.
    64-bit types (long, double, and promoted float) require even-aligned register pairs.
    """
    idx = 0
    for k in args_kinds:
        if k in _WIDE_OR_FP_KINDS:
            idx += (first_reg + idx) & 1
            idx += 2
        else:
            idx += 1
    return idx


def read_args32(
    jni: "JNIEnv",
    regs: "RegistersMapping",
    args: List[int],
    args_kinds: Tuple[ArgKind, ...],
    first_reg: int = 3
) -> List:
    if not args_kinds:
        return []

    result = []
    idx = 0
    total = len(args)
    get_ref = jni.get_reference

    for k in args_kinds:
        if idx >= total:
            break

        if k in _WIDE_OR_FP_KINDS:
            idx += (first_reg + idx) & 1
            if idx + 1 >= total:
                break

            v = (args[idx + 1] << 32) | (args[idx] & 0xFFFFFFFF)
            if k == ArgKind.LONG:
                if v & 0x8000000000000000:
                    v -= 0x10000000000000000
            else:
                v = _double_from_bits(v)

            result.append(v)
            idx += 2

        elif k == ArgKind.OBJECT:
            ref = get_ref(args[idx])
            result.append(JAVA_NULL if ref is None else ref.value)
            idx += 1

        else:
            result.append(_unpack_int(k, args[idx]))
            idx += 1

    return result


def count_arg_words64(args_kinds: Tuple[ArgKind, ...]) -> int:
    """
    Counts how many integer registers / stack slots the arguments need on ARM64.
    Floating point types travel in vector/SIMD registers.
    """
    return sum(1 for k in args_kinds if k not in (ArgKind.FLOAT, ArgKind.DOUBLE))


def read_args64(
    jni: "JNIEnv",
    regs: "RegistersMapping",
    args: List[int],
    args_kinds: Tuple[ArgKind, ...]
) -> List:
    if not args_kinds:
        return []

    result = []
    get_ref = jni.get_reference
    gp = 0
    fp = 0
    fp_regs = regs.float_arguments

    for k in args_kinds:
        if k in (ArgKind.FLOAT, ArgKind.DOUBLE):
            if fp >= len(fp_regs):
                raise NotImplementedError("More than 8 float/double arguments in variadic JNI call")
            raw_fp_bits = regs._read_reg_fast(fp_regs[fp])
            result.append(_double_from_bits(raw_fp_bits))
            fp += 1
            continue

        if gp >= len(args):
            break
        raw = args[gp]
        gp += 1

        if k == ArgKind.OBJECT:
            ref = get_ref(raw)
            result.append(JAVA_NULL if ref is None else ref.value)
        elif k == ArgKind.LONG:
            if raw & 0x8000000000000000:
                raw -= 0x10000000000000000
            result.append(raw)
        else:
            result.append(_unpack_int(k, raw))

    return result


# =========================================================================
# 2. VA_LIST CALLS (Call<T>MethodV)
# =========================================================================

def read_args_v32(
    jni: "JNIEnv",
    mem: "MemoryMap",
    args_ptr: int,
    args_kinds: Tuple[ArgKind, ...]
) -> List:
    """Reads arguments from a 32-bit va_list using atomic MemoryMap methods."""
    if not args_kinds:
        return []

    res = []
    p = args_ptr
    get_ref = jni.get_reference

    for k in args_kinds:
        if k in _WIDE_OR_FP_KINDS:
            p += p & 4  # 8-byte alignment
            raw64 = mem.read_u64(p)
            p += 8

            if k == ArgKind.LONG:
                # Signed 64-bit int
                if raw64 & 0x8000000000000000:
                    raw64 -= 0x10000000000000000
                res.append(raw64)
            else:
                res.append(_double_from_bits(raw64))

        elif k == ArgKind.OBJECT:
            raw = mem.read_u32(p)
            ref = get_ref(raw)
            res.append(JAVA_NULL if ref is None else ref.value)
            p += 4

        else:
            raw = mem.read_u32(p)
            res.append(_unpack_int(k, raw))
            p += 4

    return res


def read_args_v64(
    jni: "JNIEnv",
    mem: "MemoryMap",
    args_ptr: int,
    args_kinds: Tuple[ArgKind, ...]
) -> List:
    """Reads arguments from an AAPCS64 va_list structure using fast MemoryMap access."""
    if not args_kinds:
        return []

    stk, gr_top, vr_top, gr_offs, vr_offs = _STRUCT_VA_LIST64.unpack(mem.read_bytes(args_ptr, 32))
    res = []
    get_ref = jni.get_reference

    for k in args_kinds:
        if k in (ArgKind.FLOAT, ArgKind.DOUBLE):
            if vr_offs < 0:
                addr = vr_top + vr_offs
                vr_offs += 16  # Vector registers are 16 bytes wide in AAPCS64 save area
            else:
                addr = stk
                stk += 8
            raw_bits = mem.read_u64(addr)
            res.append(_double_from_bits(raw_bits))
        else:
            if gr_offs < 0:
                addr = gr_top + gr_offs
                gr_offs += 8
            else:
                addr = stk
                stk += 8

            raw = mem.read_u64(addr)
            if k == ArgKind.OBJECT:
                ref = get_ref(raw)
                res.append(JAVA_NULL if ref is None else ref.value)
            elif k == ArgKind.LONG:
                if raw & 0x8000000000000000:
                    raw -= 0x10000000000000000
                res.append(raw)
            else:
                res.append(_unpack_int(k, raw))

    return res

def _read_args_a(
    jni: "JNIEnv",
    mem: "MemoryMap",
    args_ptr: int,
    args_kinds: Tuple[ArgKind, ...],
    ptr_struct: struct.Struct
) -> List:
    if not args_kinds:
        return []

    raw = mem.read_bytes(args_ptr, _JVALUE_SLOT_SIZE * len(args_kinds))
    res = []
    get_ref = getattr(jni, 'get_reference', lambda idx: None)

    for i, k in enumerate(args_kinds):
        off = i * _JVALUE_SLOT_SIZE

        if k == ArgKind.OBJECT:
            ref_idx = ptr_struct.unpack_from(raw, off)[0]
            ref = get_ref(ref_idx)
            res.append(JAVA_NULL if ref is None else getattr(ref, 'value', ref))
        elif k == ArgKind.BOOLEAN:
            v = _JVALUE_STRUCTS[k].unpack_from(raw, off)[0]
            res.append(1 if v else 0)
        elif k in _JVALUE_STRUCTS:
            res.append(_JVALUE_STRUCTS[k].unpack_from(raw, off)[0])
        else:
            raise ValueError(f"Unknown or unsupported argument kind: {k!r}")

    return res


def read_args_a32(
    jni: "JNIEnv",
    mem: "MemoryMap",
    args_ptr: int,
    args_kinds: Tuple[ArgKind, ...]
) -> List:
    return _read_args_a(jni, mem, args_ptr, args_kinds, _STRUCT_PTR32)


def read_args_a64(
    jni: "JNIEnv",
    mem: "MemoryMap",
    args_ptr: int,
    args_kinds: Tuple[ArgKind, ...]
) -> List:
    return _read_args_a(jni, mem, args_ptr, args_kinds, _STRUCT_PTR64)