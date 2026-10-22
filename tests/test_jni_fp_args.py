import struct
import unittest
from types import SimpleNamespace

from unicorn.arm64_const import (
    UC_ARM64_REG_Q0, UC_ARM64_REG_Q1, UC_ARM64_REG_Q2, UC_ARM64_REG_Q3,
    UC_ARM64_REG_Q4, UC_ARM64_REG_Q5, UC_ARM64_REG_Q6, UC_ARM64_REG_Q7,
)

from androidemu.const import emu_const
from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.native.helpers.jni_native import (
    count_arg_words32, count_arg_words64, read_args32, read_args64, read_args_v32, read_args_v64,
)

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE

BIG = 0x0102030405060708
FLOAT = struct.unpack("<f", struct.pack("<f", 0.1))[0]      # the value a jfloat 0.1f really holds
DOUBLE = -1234.5678
VA = MEM_BASE + 0x200
GR = MEM_BASE + 0x300
VR = MEM_BASE + 0x400
Q = (UC_ARM64_REG_Q0, UC_ARM64_REG_Q1, UC_ARM64_REG_Q2, UC_ARM64_REG_Q3,
     UC_ARM64_REG_Q4, UC_ARM64_REG_Q5, UC_ARM64_REG_Q6, UC_ARM64_REG_Q7)   # v0..v7, the FP argument registers


def bits(v):
    return struct.unpack("<Q", struct.pack("<d", v))[0]


def lo_hi(v):
    v &= 0xFFFFFFFFFFFFFFFF
    return v & 0xFFFFFFFF, v >> 32


class Target(metaclass=JavaClassDef, jvm_name='test/fp/Target'):
    seen = None

    @staticmethod
    @java_method_def(name='m', args_list=['jint', 'jdouble', 'jfloat', 'jlong'], signature='(IDFJ)V', native=False)
    def m(emu, *a):
        Target.seen = a

    @staticmethod
    @java_method_def(name='f', args_list=['jfloat'], signature='(F)V', native=False)
    def f(emu, a):
        Target.seen = (a,)

    @staticmethod
    @java_method_def(name='mix', args_list=['jdouble', 'jint', 'jfloat', 'jstring', 'jdouble'],
                     signature='(DIFLjava/lang/String;D)V', native=False)
    def mix(emu, *a):
        Target.seen = a


class TestReaders(unittest.TestCase):
    """jfloat arrives promoted to double in "..." / va_list: every reader must give Python floats."""

    def setUp(self):
        self.h = Harness(emu_const.ARCH_ARM64)
        self.string = object()
        self.ref = self.h.obj_ref(self.string)
        self.types = ['jint', 'jdouble', 'jfloat', 'jlong', 'jstring']
        self.expected = [7, DOUBLE, FLOAT, BIG, self.string]

    def test_read_args_v32(self):
        # int | pad | double (8 aligned) | float promoted to double | long | ref
        data = struct.pack("<I4xddqI", 7, DOUBLE, FLOAT, BIG, self.ref)
        self.h.mu.mem_write(VA, data)
        self.assertEqual(read_args_v32(self.h.env, self.h.mu, VA, self.types), self.expected)

    def test_read_args_v64(self):
        # AAPCS64 va_list: the integer arguments in the GP save area, the FP ones in the VR save area (16 bytes each)
        gr_top, vr_top = GR + 0x40, VR + 0x40
        gp = struct.pack("<QQQ", 7, BIG, self.ref)
        fp = struct.pack("<d8xd8x", DOUBLE, FLOAT)
        self.h.mu.mem_write(VA, struct.pack("<QQQii", VA + 0x100, gr_top, vr_top, -len(gp), -len(fp)))
        self.h.mu.mem_write(gr_top - len(gp), gp)
        self.h.mu.mem_write(vr_top - len(fp), fp)
        self.assertEqual(read_args_v64(self.h.env, self.h.mu, VA, self.types), self.expected)

    def test_read_args32(self):
        # r3 = int, the double starts at the even position (abs. register 4), then the float (as double), long, ref
        words = [7, *lo_hi(bits(DOUBLE)), *lo_hi(bits(FLOAT)), *lo_hi(BIG), self.ref]
        self.assertEqual(count_arg_words32(self.types), len(words) + 0)
        self.assertEqual(read_args32(self.h.env, self.h.mu, words, self.types), self.expected)

    def test_read_args64_takes_floating_point_arguments_from_the_vector_registers(self):
        mu = self.h.mu
        mu.reg_write(Q[0], bits(DOUBLE))
        mu.reg_write(Q[1], bits(FLOAT))
        # the integer arguments are x3, x4, x5.. in order, whatever floating point arguments are between them
        self.assertEqual(read_args64(self.h.env, mu, [7, BIG, self.ref], self.types), self.expected)
        self.assertEqual(count_arg_words64(self.types), 3)

    def test_read_args64_interleaved(self):
        mu = self.h.mu
        mu.reg_write(Q[0], bits(1.5))
        mu.reg_write(Q[1], bits(FLOAT))
        got = read_args64(self.h.env, mu, [3, self.ref], ['jdouble', 'jint', 'jfloat', 'jstring'])
        self.assertEqual(got, [1.5, 3, FLOAT, self.string])

    def test_read_args64_without_floating_point_arguments_is_unchanged(self):
        got = read_args64(self.h.env, self.h.mu, [3, self.ref, BIG], ['jint', 'jstring', 'jlong'])
        self.assertEqual(got, [3, self.string, BIG])

    def test_too_many_floating_point_arguments_are_rejected(self):
        with self.assertRaises(NotImplementedError):
            read_args64(self.h.env, self.h.mu, [], ['jdouble'] * 9)

    def test_values_are_floats_not_bit_patterns(self):
        got = read_args_v32(self.h.env, self.h.mu, VA, ['jdouble'])
        self.assertIsInstance(got[0], float)


class TestEveryCallForm(unittest.TestCase):
    """The same Java method, the same native arguments, three ways of passing them: the mock must see the same values."""

    ITEMS = [('jint', 7), ('jdouble', DOUBLE), ('jfloat', FLOAT), ('jlong', BIG)]
    EXPECTED = (7, DOUBLE, FLOAT, BIG)

    def plain(self, h, cref, mid, items, fname="call_static_void_method"):
        if h.arch == emu_const.ARCH_ARM64:
            fp = 0
            gp = []
            for t, v in items:
                if t in ('jdouble', 'jfloat'):
                    h.mu.reg_write(Q[fp], bits(v))
                    fp += 1
                else:
                    gp.append(v)
            return h.call(fname, 0, cref, mid, *gp)
        words = []
        for t, v in items:
            if t in ('jdouble', 'jfloat', 'jlong'):
                if (3 + len(words)) & 1:
                    words.append(0xDEAD)               # 64 bit values start at an even register / stack position
                words += list(lo_hi(bits(v) if t != 'jlong' else v))
            else:
                words.append(v)
        return h.call(fname, 0, cref, mid, *words)

    def va_list(self, h, cref, mid, items, fname="call_static_void_method"):
        if h.arch == emu_const.ARCH_ARM32:
            data = bytearray()
            for t, v in items:
                if t in ('jdouble', 'jfloat', 'jlong'):
                    data += b"\0" * ((-len(data)) % 8)
                    data += struct.pack("<Q", bits(v) if t != 'jlong' else v)
                else:
                    data += struct.pack("<I", v)
            h.mu.mem_write(VA, bytes(data))
            return h.call(fname + "_v", 0, cref, mid, VA)
        gp = b"".join(struct.pack("<Q", v) for t, v in items if t not in ('jdouble', 'jfloat'))
        fp = b"".join(struct.pack("<d8x", v) for t, v in items if t in ('jdouble', 'jfloat'))
        gr_top, vr_top = GR + 0x40, VR + 0x40
        h.mu.mem_write(VA, struct.pack("<QQQii", VA + 0x100, gr_top, vr_top, -len(gp), -len(fp)))
        h.mu.mem_write(gr_top - len(gp), gp)
        h.mu.mem_write(vr_top - len(fp), fp)
        return h.call(fname + "_v", 0, cref, mid, VA)

    def jvalues(self, h, cref, mid, items, fname="call_static_void_method"):
        h.write_jvalues(items)
        return h.call(fname + "_a", 0, cref, mid, MEM_BASE)

    def test_all_forms_give_the_same_python_values(self):
        for form in ("plain", "va_list", "jvalues"):
            for arch in ARCHES:
                with self.subTest(form=form, arch=arch):
                    h = Harness(arch)
                    cref = h.add_class(Target)
                    mid = Target.find_method('m', '(IDFJ)V').jvm_id
                    Target.seen = None
                    getattr(self, form)(h, cref, mid, self.ITEMS)
                    self.assertEqual(Target.seen, self.EXPECTED)
                    self.assertIsInstance(Target.seen[1], float)
                    self.assertIsInstance(Target.seen[2], float)

    def test_a_float_as_the_first_argument(self):
        # ARM32: abs. register 3 is odd, so the promoted double skips r3 and lives on the stack (words: pad, lo, hi)
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h = Harness(arch)
                cref = h.add_class(Target)
                mid = Target.find_method('f', '(F)V').jvm_id
                Target.seen = None
                self.plain(h, cref, mid, [('jfloat', FLOAT)])
                self.assertEqual(Target.seen, (FLOAT,))

    def test_word_counts(self):
        self.assertEqual(count_arg_words32(['jfloat']), 3)                 # skipped r3 + 2 words
        self.assertEqual(count_arg_words32(['jfloat', 'jint']), 4)
        self.assertEqual(count_arg_words32(['jint', 'jfloat']), 3)         # r3, then the double at an even position
        self.assertEqual(count_arg_words32(['jdouble', 'jdouble']), 5)
        self.assertEqual(count_arg_words32([]), 0)
        self.assertEqual(count_arg_words64(['jdouble', 'jfloat']), 0)
        self.assertEqual(count_arg_words64(['jint', 'jdouble', 'jlong', 'jstring']), 3)

    def test_arm64_plain_with_floating_point_arguments_between_other_arguments(self):
        h = Harness(emu_const.ARCH_ARM64)
        cref = h.add_class(Target)
        string = object()
        mid = Target.find_method('mix', '(DIFLjava/lang/String;D)V').jvm_id
        h.mu.reg_write(Q[0], bits(1.5))        # 1st FP argument  -> v0
        h.mu.reg_write(Q[1], bits(FLOAT))      # 2nd FP argument  -> v1
        h.mu.reg_write(Q[2], bits(-8.25))      # 3rd FP argument  -> v2
        h.call("call_static_void_method", 0, cref, mid, 5, h.obj_ref(string))
        self.assertEqual(Target.seen[:3], (1.5, 5, FLOAT))
        self.assertIs(Target.seen[3], string)
        self.assertEqual(Target.seen[4], -8.25)


class TestVectorRegistersOnRealUnicorn(unittest.TestCase):
    """The fake Uc cannot prove that real Unicorn returns a Q register as an integer; this does (skipped without Unicorn)."""

    def test_q_registers_are_readable_as_integers(self):
        try:
            import unicorn
            mu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        except Exception as e:
            self.skipTest(f"real unicorn is not available: {e}")
        mu.reg_write(Q[0], bits(DOUBLE))
        mu.reg_write(Q[7], bits(FLOAT))
        jni = SimpleNamespace(get_reference=lambda idx: None)
        got = read_args64(jni, mu, [], ['jdouble'] * 8)
        self.assertEqual((got[0], got[7]), (DOUBLE, FLOAT))


if __name__ == "__main__":
    unittest.main()
