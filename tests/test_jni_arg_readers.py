import struct
import unittest

from androidemu.java.class_def import JavaClassDef
from androidemu.java.jvm.constants import JAVA_NULL
from androidemu.native.helpers.jni_native import (
    _arg_kind, read_args32, read_args64, read_args_v32, read_args_v64,
)

try:
    from .jni_harness import Harness, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, MEM_BASE

from androidemu.const import emu_const


class Dummy(metaclass=JavaClassDef, jvm_name='test/readers/Dummy'):
    pass


TYPES = ['jshort', 'jstring', 'jclass', 'jchar', 'jbyteArray', 'jint']


class TestArgKind(unittest.TestCase):

    def test_known_names_are_matched_in_full(self):
        expected = {
            'jlong': 'l', 'jdouble': 'd', 'jfloat': 'f',
            'jboolean': 'i', 'jbyte': 'i', 'jchar': 'i', 'jshort': 'i', 'jint': 'i',   # jshort used to be 's'
            'jobject': 'o', 'jstring': 'o', 'jclass': 'o', 'jthrowable': 'o', 'jarray': 'o',
            'jbyteArray': 'o', 'jlongArray': 'o', 'jobjectArray': 'o', 'jintArray': 'o',  # jlongArray used to be 'l'
        }
        for name, kind in expected.items():
            with self.subTest(name=name):
                self.assertEqual(_arg_kind(name), kind)


class TestReaders(unittest.TestCase):
    """
    The same argument list through every reader: a short must stay a number (it used to be looked
    up as a reference), a jclass / an array must be resolved to the object behind the reference.
    """

    def setUp(self):
        self.h = Harness(emu_const.ARCH_ARM64)
        self.string = object()
        self.array = object()
        self.string_ref = self.h.obj_ref(self.string)
        self.array_ref = self.h.obj_ref(self.array)
        self.h.add_class(Dummy)
        self.class_ref = self.h.class_ref(Dummy)
        self.cls_obj = self.h.env.get_reference(self.class_ref).value
        # 5 is a perfectly valid short whose value is NOT a live reference index
        self.raw = [5, self.string_ref, self.class_ref, 0xFFFF, self.array_ref, 7]
        self.expected = [5, self.string, self.cls_obj, 0xFFFF, self.array, 7]

    def test_read_args32(self):
        self.assertEqual(read_args32(self.h.env, self.h.mu, self.raw, TYPES), self.expected)

    def test_read_args64(self):
        self.assertEqual(read_args64(self.h.env, self.h.mu, self.raw, TYPES), self.expected)

    def test_read_args_v32(self):
        self.h.mu.mem_write(MEM_BASE, struct.pack("<6I", *self.raw))
        self.assertEqual(read_args_v32(self.h.env, self.h.mu, MEM_BASE, TYPES), self.expected)

    def test_read_args_v64(self):
        # AAPCS64 va_list: __stack, __gr_top, __vr_top, __gr_offs, __vr_offs
        gr_top = MEM_BASE + 0x100
        gr_offs = -8 * len(self.raw)
        self.h.mu.mem_write(MEM_BASE, struct.pack("<QQQii", MEM_BASE + 0x200, gr_top, MEM_BASE + 0x180, gr_offs, 0))
        self.h.mu.mem_write(gr_top + gr_offs, struct.pack("<6Q", *self.raw))
        self.assertEqual(read_args_v64(self.h.env, self.h.mu, MEM_BASE, TYPES), self.expected)

    def test_null_references_still_give_java_null(self):
        raw = [0, 0, 0]
        types = ['jstring', 'jclass', 'jbyteArray']
        self.assertEqual(read_args64(self.h.env, self.h.mu, raw, types), [JAVA_NULL] * 3)
        self.assertEqual(read_args32(self.h.env, self.h.mu, raw, types), [JAVA_NULL] * 3)

    def test_long_arrays_are_not_wide_arguments(self):
        # 'jlongArray'[1] is 'l': the 32 bit readers used to treat it as a 64 bit jlong
        raw = [self.array_ref, 7]
        got = read_args32(self.h.env, self.h.mu, raw, ['jlongArray', 'jint'])
        self.assertEqual(got, [self.array, 7])

    def test_existing_argument_kinds_are_unchanged(self):
        raw = [3, self.string_ref]          # jint, jstring
        self.assertEqual(read_args64(self.h.env, self.h.mu, raw, ['jint', 'jstring']), [3, self.string])
        # jlong in two 32 bit registers (r3 is the first one here: the pair starts on an even register)
        raw = [0, 0x89ABCDEF, 0x01234567]
        got = read_args32(self.h.env, self.h.mu, raw, ['jint', 'jlong'])
        self.assertEqual(got, [0, 0x0123456789ABCDEF])


class TestNarrowArguments(unittest.TestCase):
    """Narrow JNI integers must reach the mocks with Java semantics, not raw register bits."""

    def setUp(self):
        self.h = Harness(emu_const.ARCH_ARM64)

    def test_read_args32_narrow_types(self):
        raw = [0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0x1FFFE, 2]
        got = read_args32(
            self.h.env, self.h.mu, raw,
            ['jbyte', 'jshort', 'jint', 'jchar', 'jboolean'],
        )
        self.assertEqual(got, [-5, -2, -1, 0xFFFE, 1])

    def test_read_args32_negative_long(self):
        raw = [0, 0xFFFFFFFF, 0xFFFFFFFF]
        self.assertEqual(
            read_args32(self.h.env, self.h.mu, raw, ['jint', 'jlong']),
            [0, -1],
        )

    def test_read_args64_narrow_types(self):
        raw = [0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0x1FFFE, 2, 0xFFFFFFFFFFFFFFFE]
        got = read_args64(
            self.h.env, self.h.mu, raw,
            ['jbyte', 'jshort', 'jint', 'jchar', 'jboolean', 'jlong'],
        )
        self.assertEqual(got, [-5, -2, -1, 0xFFFE, 1, -2])

    def test_read_args_v32_narrow_types(self):
        raw = [0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0x1FFFE, 2]
        self.h.mu.mem_write(MEM_BASE, struct.pack("<5I", *raw))
        got = read_args_v32(
            self.h.env, self.h.mu, MEM_BASE,
            ['jbyte', 'jshort', 'jint', 'jchar', 'jboolean'],
        )
        self.assertEqual(got, [-5, -2, -1, 0xFFFE, 1])

    def test_read_args_v32_negative_long(self):
        # 4 bytes of jint, 4 bytes of alignment padding, then the signed 64 bit jlong
        self.h.mu.mem_write(MEM_BASE, struct.pack("<I4xq", 0, -2))
        self.assertEqual(
            read_args_v32(self.h.env, self.h.mu, MEM_BASE, ['jint', 'jlong']),
            [0, -2],
        )

    def test_read_args_v64_narrow_types(self):
        raw = [0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0x1FFFE, 2, 0xFFFFFFFFFFFFFFFE]
        gr_top = MEM_BASE + 0x100
        gr_offs = -8 * len(raw)
        self.h.mu.mem_write(
            MEM_BASE,
            struct.pack("<QQQii", MEM_BASE + 0x200, gr_top, MEM_BASE + 0x180, gr_offs, 0),
        )
        self.h.mu.mem_write(gr_top + gr_offs, struct.pack("<6Q", *raw))
        got = read_args_v64(
            self.h.env, self.h.mu, MEM_BASE,
            ['jbyte', 'jshort', 'jint', 'jchar', 'jboolean', 'jlong'],
        )
        self.assertEqual(got, [-5, -2, -1, 0xFFFE, 1, -2])


if __name__ == "__main__":
    unittest.main()
