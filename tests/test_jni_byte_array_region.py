import unittest

from androidemu.java.classes.java.lang.array import Array, ByteArray
from androidemu.java.jni.reference import jobject
from androidemu.const import emu_const

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE

BUF = MEM_BASE + 0x400


class TestSetByteArrayRegion(unittest.TestCase):

    def setup(self, arch, items):
        h = Harness(arch)
        arr = ByteArray(items)
        h.mu.mem_write(BUF, b"XYZ")
        return h, arr, h.obj_ref(arr)

    def test_writes_into_the_requested_region_and_keeps_the_rest(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch, bytearray(b"abcdef"))
                h.call("set_byte_array_region", 0, ref, 2, 3, BUF)
                self.assertEqual(bytes(arr.get_py_items()), b"abXYZf")

    def test_the_java_object_stays_the_same_one(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch, bytearray(b"abcdef"))
                h.call("set_byte_array_region", 0, ref, 0, 3, BUF)
                self.assertIs(h.env.get_reference(ref).value, arr)   # holders of `arr` see the change
                self.assertIs(type(arr), ByteArray)
                self.assertEqual(len(arr), 6)

    def test_start_zero_full_length_and_the_last_valid_region(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch, bytearray(b"abc"))
                h.call("set_byte_array_region", 0, ref, 0, 3, BUF)
                self.assertEqual(bytes(arr.get_py_items()), b"XYZ")
                h, arr, ref = self.setup(arch, bytearray(b"abcdef"))
                h.call("set_byte_array_region", 0, ref, 3, 3, BUF)
                self.assertEqual(bytes(arr.get_py_items()), b"abcXYZ")

    def test_other_backing_stores(self):
        for arch in ARCHES:
            with self.subTest(arch=arch, store="list"):
                h, arr, ref = self.setup(arch, [1, 2, 3, 4, 5])
                h.call("set_byte_array_region", 0, ref, 1, 3, BUF)
                self.assertEqual(list(arr.get_py_items()), [1, 0x58, 0x59, 0x5A, 5])
            with self.subTest(arch=arch, store="immutable bytes"):
                h, arr, ref = self.setup(arch, b"abcdef")
                h.call("set_byte_array_region", 0, ref, 1, 3, BUF)
                self.assertEqual(bytes(arr.get_py_items()), b"aXYZef")
                self.assertIs(h.env.get_reference(ref).value, arr)

    def test_array_class_instances_and_global_references(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h = Harness(arch)
                h.mu.mem_write(BUF, b"XYZ")
                arr = Array(bytearray(b"abcdef"))            # what NewByteArray creates
                gref = h.env.add_global_reference(jobject(arr))
                self.assertGreaterEqual(gref, 4096)
                h.call("set_byte_array_region", 0, gref, 1, 3, BUF)
                self.assertEqual(bytes(arr.get_py_items()), b"aXYZef")

    def test_new_byte_array_then_set_region(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h = Harness(arch)
                h.mu.mem_write(BUF, b"XYZ")
                ref = h.call("new_byte_array", 0, 5)
                h.call("set_byte_array_region", 0, ref, 1, 3, BUF)
                self.assertEqual(bytes(h.env.get_reference(ref).value.get_py_items()), b"\x00XYZ\x00")

    def test_zero_length_is_a_no_op_even_with_a_null_buffer(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch, bytearray(b"abc"))
                h.call("set_byte_array_region", 0, ref, 3, 0, 0)
                self.assertEqual(bytes(arr.get_py_items()), b"abc")

    def test_out_of_range_raises_and_leaves_the_array_alone(self):
        bad = [(4, 3), (7, 0), (3, 4), (0xFFFFFFFF, 1), (1, 0xFFFFFFFF)]   # the last two are -1 as a jint
        for arch in ARCHES:
            for start, length in bad:
                with self.subTest(arch=arch, start=start, length=length):
                    h, arr, ref = self.setup(arch, bytearray(b"abcdef"))
                    with self.assertRaisesRegex(IndexError, "ArrayIndexOutOfBounds"):
                        h.call("set_byte_array_region", 0, ref, start, length, BUF)
                    self.assertEqual(bytes(arr.get_py_items()), b"abcdef")

    def test_upper_register_bits_of_int_arguments_are_ignored(self):
        h, arr, ref = self.setup(emu_const.ARCH_ARM64, bytearray(b"abcdef"))
        h.call("set_byte_array_region", 0, ref, 2 | (0xDEADBEEF << 32), 3 | (0xCAFEBABE << 32), BUF)
        self.assertEqual(bytes(arr.get_py_items()), b"abXYZf")


class TestGetByteArrayRegion(unittest.TestCase):

    def setup(self, arch, items=b"abcdef"):
        h = Harness(arch)
        arr = ByteArray(bytearray(items))
        h.mu.mem_write(BUF, b"\xEE" * 8)                    # what the buffer held before
        return h, arr, h.obj_ref(arr)

    def test_copies_the_requested_region(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch)
                h.call("get_byte_array_region", 0, ref, 2, 3, BUF)
                self.assertEqual(bytes(h.mu.mem_read(BUF, 8)), b"cde" + b"\xEE" * 5)

    def test_whole_array_and_empty_region(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch)
                h.call("get_byte_array_region", 0, ref, 0, 6, BUF)
                self.assertEqual(bytes(h.mu.mem_read(BUF, 6)), b"abcdef")
                h.call("get_byte_array_region", 0, ref, 6, 0, 0)      # length 0 at the end, NULL buffer: fine

    def test_out_of_range_raises_instead_of_clamping(self):
        bad = [(4, 3), (7, 0), (3, 4), (0xFFFFFFFF, 1), (1, 0xFFFFFFFF)]
        for arch in ARCHES:
            for start, length in bad:
                with self.subTest(arch=arch, start=start, length=length):
                    h, arr, ref = self.setup(arch)
                    with self.assertRaisesRegex(IndexError, "ArrayIndexOutOfBounds"):
                        h.call("get_byte_array_region", 0, ref, start, length, BUF)
                    self.assertEqual(bytes(h.mu.mem_read(BUF, 8)), b"\xEE" * 8)   # nothing was written


if __name__ == "__main__":
    unittest.main()
