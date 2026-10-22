"""
Tiny fakes that let tests call JNIEnv function-table entries directly.

No ELF is loaded and no ARM code is executed: the "native code" side of a JNI call is
reproduced by filling the argument registers (and a jvalue array in fake memory) exactly as
a compiled caller would, then invoking the same bound method the Hooker would call.
"""
import struct
from types import SimpleNamespace

from unicorn.arm64_const import UC_ARM64_REG_Q0, UC_ARM64_REG_Q31

from androidemu.const import emu_const
from androidemu.core.registers import RegistersMapping
from androidemu.java.classloader import JavaClassLoader
from androidemu.java.classes.java.lang.array import (
    Array, BooleanArray, ByteArray, CharArray, DoubleArray, FloatArray, IntArray, LongArray, ShortArray,
)
from androidemu.java.classes.java.lang.string import String
from androidemu.java.jni.main import JNIEnv
from androidemu.java.jni.reference import jobject, jclass

ARCHES = (emu_const.ARCH_ARM32, emu_const.ARCH_ARM64)
ARRAY_CLASSES = (BooleanArray, ByteArray, CharArray, ShortArray, IntArray, LongArray, FloatArray, DoubleArray)

MEM_BASE = 0x10000
MEM_SIZE = 0x4000
HEAP_ADDR = MEM_BASE + 0x1000   # the arena of FakeLibC.malloc
STACK_ADDR = MEM_BASE + 0xC00   # where call() puts arguments that do not fit into registers

# jvalue is a union, every element occupies 8 bytes on both ABIs (little endian).
_JVALUE_FMT = {
    "jboolean": "<B", "jbyte": "<b", "jchar": "<H", "jshort": "<h",
    "jint": "<i", "jlong": "<q", "jfloat": "<f", "jdouble": "<d",
}


class FakeMu:
    """Just enough of unicorn.Uc: registers and one flat memory block."""

    def __init__(self, arch: int):
        self._arch = arch
        self._regs = {}
        self._mem = bytearray(MEM_SIZE)

    def reg_read(self, reg_id):
        return self._regs.get(reg_id, 0)

    def reg_write(self, reg_id, value):
        if UC_ARM64_REG_Q0 <= reg_id <= UC_ARM64_REG_Q31:
            bits = 128
        else:
            bits = 32 if self._arch == emu_const.ARCH_ARM32 else 64
        self._regs[reg_id] = value & ((1 << bits) - 1)

    def mem_read(self, addr, size):
        off = addr - MEM_BASE
        if off < 0 or off + size > MEM_SIZE:
            raise RuntimeError(f"FakeMu: read outside of the scratch block ({addr:#x}, {size})")
        return bytearray(self._mem[off:off + size])

    def mem_write(self, addr, data):
        off = addr - MEM_BASE
        if off < 0 or off + len(data) > MEM_SIZE:
            raise RuntimeError(f"FakeMu: write outside of the scratch block ({addr:#x}, {len(data)})")
        self._mem[off:off + len(data)] = data


class FakeLibC:
    """Stands in for LibC (which would run the emulated libc's malloc/free): a bump allocator that remembers what was freed."""

    def __init__(self):
        self.next = HEAP_ADDR
        self.sizes = {}
        self.freed = []

    def malloc(self, size: int) -> int:
        ptr = self.next
        self.next += (size + 15) & ~15
        self.sizes[ptr] = size
        return ptr

    def free(self, ptr: int):
        self.freed.append(ptr)


class FakeHooker:
    def write_function_table(self, table):
        return 0, 0


class Harness:
    """JNIEnv + a fake emulator for one architecture."""

    def __init__(self, arch: int):
        self.arch = arch
        self.ptr_size = 8 if arch == emu_const.ARCH_ARM64 else 4
        self.mu = FakeMu(arch)
        self.loader = JavaClassLoader()
        # JNIEnv looks these two up once, in its constructor (NewByteArray & co. create Array objects)
        self.loader.add_class(String)
        self.loader.add_class(Array)
        for array_class in ARRAY_CLASSES:
            self.loader.add_class(array_class)
        self.emu = SimpleNamespace(
            arch=arch,
            mu=self.mu,
            registers=RegistersMapping(self.mu, arch),
            java_vm=SimpleNamespace(jni_env=None),
        )
        self.env = JNIEnv(self.emu, self.loader, FakeHooker())
        self.emu.java_vm.jni_env = self.env
        self.libc = FakeLibC()
        self.env._JNIEnv__libc = self.libc

    # --- references -------------------------------------------------------------------
    def add_class(self, pyclazz):
        self.loader.add_class(pyclazz)
        return self.class_ref(pyclazz)

    def class_ref(self, pyclazz):
        return self.env.add_local_reference(jclass(pyclazz.class_object))

    def obj_ref(self, obj):
        return self.env.add_local_reference(jobject(obj))

    # --- calling ----------------------------------------------------------------------
    def call(self, name, *args):
        """Calls env.<name>(emu) with `args` in r0..r3 / x0..x7 (+ stack), returns r0 / x0."""
        regs = self.emu.registers
        max_regs = len(regs.arguments)
        for i, value in enumerate(args[:max_regs]):
            setattr(regs, f"v_reg_{i}", value)
        if len(args) > max_regs:  # the rest travels on the stack, like a compiled caller does
            fmt = "<Q" if self.ptr_size == 8 else "<I"
            self.mu.mem_write(STACK_ADDR, b"".join(struct.pack(fmt, a) for a in args[max_regs:]))
            regs.v_sp = STACK_ADDR
        getattr(self.env, name)(self.emu)
        return regs.v_reg_0

    def write_jvalues(self, items, addr=MEM_BASE):
        """
        Lays out a jvalue[] the way a C caller does: only the bytes of the union member that
        is used are written, the rest of the 8 byte slot is left as garbage (0xA5).
        """
        for i, (jtype, value) in enumerate(items):
            slot = bytearray(b"\xA5" * 8)
            if jtype in _JVALUE_FMT:
                data = struct.pack(_JVALUE_FMT[jtype], value)
            else:  # references
                data = struct.pack("<I" if self.ptr_size == 4 else "<Q", value)
            slot[:len(data)] = data
            self.mu.mem_write(addr + 8 * i, bytes(slot))
        return addr

    # --- FP return --------------------------------------------------------------------
    def fp_return_bits(self, is_double: bool) -> int:
        """Raw bits of a float/double return value, wherever the ABI keeps it."""
        if self.arch == emu_const.ARCH_ARM64:
            q0 = self.mu.reg_read(UC_ARM64_REG_Q0)
            return q0 & (0xFFFFFFFFFFFFFFFF if is_double else 0xFFFFFFFF)
        regs = self.emu.registers
        if is_double:
            return (regs.v_reg_1 << 32) | regs.v_reg_0
        return regs.v_reg_0
