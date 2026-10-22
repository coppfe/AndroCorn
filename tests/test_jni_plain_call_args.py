import struct
import unittest

from androidemu.const import emu_const
from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def

try:
    from .jni_harness import Harness, ARCHES
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES


class Target(metaclass=JavaClassDef, jvm_name='test/plain/Target'):
    seen = None

    @staticmethod
    @java_method_def(name='j', args_list=['jlong'], signature='(J)V', native=False)
    def j(emu, a):
        Target.seen = (a,)

    @staticmethod
    @java_method_def(name='ijI', args_list=['jint', 'jlong', 'jint'], signature='(IJI)V', native=False)
    def ij_i(emu, a, b, c):
        Target.seen = (a, b, c)

    @staticmethod
    @java_method_def(name='neg', args_list=['jbyte', 'jshort', 'jint', 'jlong'], signature='(BSIJ)V', native=False)
    def neg(emu, b, s, i, j):
        Target.seen = (b, s, i, j)

    @staticmethod
    @java_method_def(name='jj', args_list=['jlong', 'jlong'], signature='(JJ)V', native=False)
    def jj(emu, a, b):
        Target.seen = (a, b)

    @staticmethod
    @java_method_def(name='iii', args_list=['jint', 'jint', 'jint', 'jint', 'jint'], signature='(IIIII)V', native=False)
    def iiiii(emu, *a):
        Target.seen = a

    @staticmethod
    @java_method_def(name='none', args_list=[], signature='()V', native=False)
    def none(emu):
        Target.seen = ()


def lo_hi(v):
    v &= 0xFFFFFFFFFFFFFFFF
    return v & 0xFFFFFFFF, v >> 32


class TestPlainVariadicArguments(unittest.TestCase):
    """CallStaticVoidMethod(env, cls, mid, ...): where the variadic arguments are found."""

    def setUp(self):
        Target.seen = None

    def call(self, arch, name, sig, regs_after_mid):
        h = Harness(arch)
        cref = h.add_class(Target)
        mid = Target.find_method(name, sig).jvm_id
        h.call("call_static_void_method", 0, cref, mid, *regs_after_mid)
        return Target.seen

    def test_arm32_long_goes_to_an_even_position_after_a_skipped_register(self):
        # r3 is skipped (a jlong needs an even register pair), the value is on the stack
        lo, hi = lo_hi(0x1122334455667788)
        self.assertEqual(self.call(emu_const.ARCH_ARM32, 'j', '(J)V', (0xDEAD, lo, hi)), (0x1122334455667788,))

    def test_arm32_negative_long(self):
        lo, hi = lo_hi(-2)
        self.assertEqual(self.call(emu_const.ARCH_ARM32, 'j', '(J)V', (0xDEAD, lo, hi)), (-2,))

    def test_arm32_int_then_long_then_int(self):
        lo, hi = lo_hi(-(1 << 40))
        # r3 = int, then the long is already at an even position (stack slots 0,1), then the last int
        self.assertEqual(self.call(emu_const.ARCH_ARM32, 'ijI', '(IJI)V', (7, lo, hi, 9)), (7, -(1 << 40), 9))

    def test_arm32_two_longs(self):
        a, b = lo_hi(0x0102030405060708), lo_hi(-1)
        self.assertEqual(self.call(emu_const.ARCH_ARM32, 'jj', '(JJ)V', (0xDEAD, a[0], a[1], b[0], b[1])),
                         (0x0102030405060708, -1))

    def test_negative_narrow_arguments(self):
        lo, hi = lo_hi(-2)
        # r3 = jbyte, then jshort/jint and the even aligned jlong pair on the stack
        self.assertEqual(
            self.call(emu_const.ARCH_ARM32, 'neg', '(BSIJ)V',
                      (0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, lo, hi)),
            (-5, -2, -1, -2),
        )
        self.assertEqual(
            self.call(emu_const.ARCH_ARM64, 'neg', '(BSIJ)V',
                      (0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFE)),
            (-5, -2, -1, -2),
        )

    def test_arm32_ints_only_are_unchanged(self):
        self.assertEqual(self.call(emu_const.ARCH_ARM32, 'iii', '(IIIII)V', (1, 2, 3, 4, 5)), (1, 2, 3, 4, 5))

    def test_arm64_long_is_one_register(self):
        self.assertEqual(self.call(emu_const.ARCH_ARM64, 'j', '(J)V', (0x1122334455667788,)), (0x1122334455667788,))
        # raw register value, as the readers always gave it on ARM64
        self.assertEqual(self.call(emu_const.ARCH_ARM64, 'ijI', '(IJI)V', (7, 5, 9)), (7, 5, 9))

    def test_no_arguments(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                self.assertEqual(self.call(arch, 'none', '()V', ()), ())


if __name__ == "__main__":
    unittest.main()
