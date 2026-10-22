import struct
import unittest
from array import array

from androidemu.const import emu_const
from androidemu.java.classes.java.lang.array import (
    Array, BooleanArray, CharArray, DoubleArray, FloatArray, IntArray, LongArray, ShortArray,
)

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE

BUF = MEM_BASE + 0x500


def f32(v):
    return struct.unpack("<f", struct.pack("<f", v))[0]


# kind, JNI function name part, array class, struct format, items (5), the 2 native values SetRegion gets
# at positions 1..2, and what the array must then hold at those positions
SAMPLES = [
    ("Z", "boolean", BooleanArray, "B", [1, 0, 1, 1, 0], [7, 0], [1, 0]),
    ("C", "char", CharArray, "H", [65, 0xFFFE, 7, 0, 1], [0xFFFF, 66], [0xFFFF, 66]),
    ("S", "short", ShortArray, "h", [-2, 300, 7, 0, 1], [-32768, 5], [-32768, 5]),
    ("I", "int", IntArray, "i", [-5, 1 << 30, 7, 0, 1], [-(1 << 31), 9], [-(1 << 31), 9]),
    ("J", "long", LongArray, "q", [-(1 << 40), 1 << 62, 7, 0, 1], [-1, 1 << 40], [-1, 1 << 40]),
    ("F", "float", FloatArray, "f", [1.5, f32(0.1), 7.0, 0.0, -2.0], [3.5, f32(0.2)], [3.5, f32(0.2)]),
    ("D", "double", DoubleArray, "d", [-2.25, 0.1, 7.0, 0.0, 1e300], [3.5, 0.2], [3.5, 0.2]),
]


def native(fmt, values):
    return struct.pack(f"<{len(values)}{fmt}", *values)


class TestNewArray(unittest.TestCase):

    def test_creates_a_zeroed_array_of_the_right_class(self):
        for kind, name, cls, fmt, *_ in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h = Harness(arch)
                    ref = h.call(f"new_{name}_array", 0, 4)
                    arr = h.env.get_reference(ref).value
                    self.assertIs(type(arr), cls)
                    zero = 0.0 if kind in "FD" else 0
                    self.assertEqual(arr.get_py_items(), [zero] * 4)
                    self.assertEqual(h.call("get_array_length", 0, ref), 4)
                    if kind in "FD":
                        self.assertTrue(all(isinstance(v, float) for v in arr.get_py_items()))

    def test_empty_array_and_garbage_in_the_upper_register_bits(self):
        h = Harness(emu_const.ARCH_ARM64)
        self.assertEqual(len(h.env.get_reference(h.call("new_int_array", 0, 0)).value), 0)
        ref = h.call("new_int_array", 0, 3 | (0xDEADBEEF << 32))
        self.assertEqual(len(h.env.get_reference(ref).value), 3)

    def test_negative_length(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h = Harness(arch)
                with self.assertRaisesRegex(ValueError, "NegativeArraySizeException"):
                    h.call("new_char_array", 0, 0xFFFFFFFF)

    def test_an_unregistered_array_class_is_reported(self):
        h = Harness(ARCHES[1])
        h.loader.class_by_name.pop("[S")
        with self.assertRaisesRegex(RuntimeError, r"\[S"):
            h.call("new_short_array", 0, 1)


class TestRegions(unittest.TestCase):

    def make(self, arch, cls, items):
        h = Harness(arch)
        arr = cls(list(items))
        return h, arr, h.obj_ref(arr)

    def test_get_region_writes_native_values(self):
        for kind, name, cls, fmt, items, _, _ in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h, arr, ref = self.make(arch, cls, items)
                    h.mu.mem_write(BUF, b"\xEE" * 64)
                    h.call(f"get_{name}_array_region", 0, ref, 1, 3, BUF)
                    size = struct.calcsize(fmt)
                    self.assertEqual(bytes(h.mu.mem_read(BUF, 3 * size)), native(fmt, items[1:4]))
                    self.assertEqual(bytes(h.mu.mem_read(BUF + 3 * size, 8)), b"\xEE" * 8)   # nothing beyond the region

    def test_set_region_is_in_place_and_keeps_the_rest(self):
        for kind, name, cls, fmt, items, set_native, expected in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h, arr, ref = self.make(arch, cls, items)
                    h.mu.mem_write(BUF, native(fmt, set_native))
                    h.call(f"set_{name}_array_region", 0, ref, 1, 2, BUF)
                    self.assertEqual(arr.get_py_items(), [items[0], *expected, items[3], items[4]])
                    self.assertIs(h.env.get_reference(ref).value, arr)
                    self.assertEqual(len(arr), 5)

    def test_java_semantics_of_the_items(self):
        # short/int/long come back signed, char unsigned, boolean as 0/1, float as float32
        h, arr, ref = self.make(ARCHES[1], ShortArray, [0, 0])
        h.mu.mem_write(BUF, b"\xFE\xFF\x00\x80")
        h.call("set_short_array_region", 0, ref, 0, 2, BUF)
        self.assertEqual(arr.get_py_items(), [-2, -32768])
        h, arr, ref = self.make(ARCHES[1], CharArray, [0, 0])
        h.mu.mem_write(BUF, b"\xFE\xFF\x00\x80")
        h.call("set_char_array_region", 0, ref, 0, 2, BUF)
        self.assertEqual(arr.get_py_items(), [0xFFFE, 0x8000])
        h, arr, ref = self.make(ARCHES[1], BooleanArray, [0, 0, 0])
        h.mu.mem_write(BUF, b"\x00\x01\xFF")
        h.call("set_boolean_array_region", 0, ref, 0, 3, BUF)
        self.assertEqual(arr.get_py_items(), [0, 1, 1])

    def test_unsigned_or_python_style_items_are_masked_when_read(self):
        h, arr, ref = self.make(ARCHES[1], ShortArray, [65534, True, -1])
        h.call("get_short_array_region", 0, ref, 0, 3, BUF)
        self.assertEqual(bytes(h.mu.mem_read(BUF, 6)), native("h", [-2, 1, -1]))
        h, arr, ref = self.make(ARCHES[1], BooleanArray, [True, False, 5])
        h.call("get_boolean_array_region", 0, ref, 0, 3, BUF)
        self.assertEqual(bytes(h.mu.mem_read(BUF, 3)), b"\x01\x00\x01")
        h, arr, ref = self.make(ARCHES[1], FloatArray, [2, 1e40, -1e40])     # ints are fine, out of range is +-inf
        h.call("get_float_array_region", 0, ref, 0, 3, BUF)
        self.assertEqual(bytes(h.mu.mem_read(BUF, 12)), native("f", [2.0, float("inf"), float("-inf")]))

    def test_other_item_stores(self):
        h = Harness(ARCHES[1])
        h.mu.mem_write(BUF, native("i", [11, 22]))
        # array.array keeps its type code
        arr = IntArray(array("i", [1, 2, 3, 4]))
        h.call("set_int_array_region", 0, h.obj_ref(arr), 1, 2, BUF)
        self.assertEqual((type(arr.get_py_items()), list(arr.get_py_items())), (array, [1, 11, 22, 4]))
        # an immutable store is swapped inside the same Java object
        arr = IntArray((1, 2, 3, 4))
        ref = h.obj_ref(arr)
        h.call("set_int_array_region", 0, ref, 1, 2, BUF)
        self.assertEqual(list(arr.get_py_items()), [1, 11, 22, 4])
        self.assertIs(h.env.get_reference(ref).value, arr)
        # an Array without element type information is taken at the word of the function
        arr = Array([1, 2, 3, 4])
        h.call("get_int_array_region", 0, h.obj_ref(arr), 0, 4, BUF)
        self.assertEqual(bytes(h.mu.mem_read(BUF, 16)), native("i", [1, 2, 3, 4]))

    def test_empty_region_and_boundaries(self):
        for kind, name, cls, fmt, items, set_native, _ in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h, arr, ref = self.make(arch, cls, items)
                    h.call(f"get_{name}_array_region", 0, ref, 5, 0, 0)      # empty region at the end, NULL buffer
                    h.call(f"set_{name}_array_region", 0, ref, 5, 0, 0)
                    h.mu.mem_write(BUF, native(fmt, set_native))
                    h.call(f"set_{name}_array_region", 0, ref, 3, 2, BUF)    # last valid region
                    self.assertEqual(len(arr), 5)

    def test_out_of_range_raises_and_changes_nothing(self):
        bad = [(4, 3), (6, 0), (3, 3), (0xFFFFFFFF, 1), (1, 0xFFFFFFFF)]
        for kind, name, cls, fmt, items, *_ in SAMPLES:
            for arch in ARCHES:
                for start, length in bad:
                    for op in ("get", "set"):
                        with self.subTest(kind=kind, arch=arch, start=start, length=length, op=op):
                            h, arr, ref = self.make(arch, cls, items)
                            h.mu.mem_write(BUF, b"\xEE" * 64)
                            with self.assertRaisesRegex(IndexError, "ArrayIndexOutOfBounds"):
                                h.call(f"{op}_{name}_array_region", 0, ref, start, length, BUF)
                            self.assertEqual(arr.get_py_items(), items)
                            self.assertEqual(bytes(h.mu.mem_read(BUF, 8)), b"\xEE" * 8)

    def test_an_array_of_another_element_type_is_rejected(self):
        h, arr, ref = self.make(ARCHES[1], CharArray, [1, 2, 3])
        with self.assertRaisesRegex(ValueError, "GetIntArrayRegion.*\\[C"):
            h.call("get_int_array_region", 0, ref, 0, 1, BUF)
        with self.assertRaisesRegex(ValueError, "SetShortArrayRegion"):
            h.call("set_short_array_region", 0, ref, 0, 1, BUF)

    def test_upper_register_bits_of_int_arguments_are_ignored(self):
        h, arr, ref = self.make(emu_const.ARCH_ARM64, IntArray, [1, 2, 3, 4])
        h.mu.mem_write(BUF, native("i", [8, 9]))
        h.call("set_int_array_region", 0, ref, 1 | (0xDEADBEEF << 32), 2 | (0xCAFEBABE << 32), BUF)
        self.assertEqual(arr.get_py_items(), [1, 8, 9, 4])

    def test_new_array_then_set_and_get_round_trip(self):
        for kind, name, cls, fmt, items, *_ in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h = Harness(arch)
                    ref = h.call(f"new_{name}_array", 0, 5)
                    h.mu.mem_write(BUF, native(fmt, items))
                    h.call(f"set_{name}_array_region", 0, ref, 0, 5, BUF)
                    h.mu.mem_write(BUF + 0x100, b"\x00" * 64)
                    h.call(f"get_{name}_array_region", 0, ref, 0, 5, BUF + 0x100)
                    self.assertEqual(bytes(h.mu.mem_read(BUF + 0x100, 5 * struct.calcsize(fmt))), native(fmt, items))
                    self.assertEqual(h.env.get_reference(ref).value.get_py_items(), items)


if __name__ == "__main__":
    unittest.main()
