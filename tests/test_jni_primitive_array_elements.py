import struct
import unittest
from array import array

from androidemu.const import emu_const
from androidemu.java.classes.java.lang.array import Array, ByteArray, CharArray, IntArray, ObjectArray
from androidemu.java.jni.constants import JNI_ABORT, JNI_COMMIT

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
    from .test_jni_primitive_arrays import SAMPLES, native
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE
    from test_jni_primitive_arrays import SAMPLES, native

IS_COPY = MEM_BASE + 0x500


class TestElements(unittest.TestCase):

    def make(self, arch, cls, items):
        h = Harness(arch)
        arr = cls(list(items))
        return h, arr, h.obj_ref(arr)

    def test_the_buffer_holds_the_native_elements(self):
        for kind, name, cls, fmt, items, *_ in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h, arr, ref = self.make(arch, cls, items)
                    ptr = h.call(f"get_{name}_array_elements", 0, ref, 0)
                    self.assertEqual(bytes(h.mu.mem_read(ptr, 5 * struct.calcsize(fmt))), native(fmt, items))
                    self.assertEqual(ptr % 8, 0)                       # suitable for a long/double

    def test_is_copy_pointer(self):
        for kind, name, cls, fmt, items, *_ in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h, arr, ref = self.make(arch, cls, items)
                    h.mu.mem_write(IS_COPY, b"\x00")
                    h.call(f"get_{name}_array_elements", 0, ref, IS_COPY)
                    self.assertEqual(bytes(h.mu.mem_read(IS_COPY, 1)), b"\x01")
                    h.call(f"get_{name}_array_elements", 0, ref, 0)      # NULL is allowed too

    def test_release_modes(self):
        for kind, name, cls, fmt, items, set_native, expected in SAMPLES:
            for mode, copies_back, frees in ((0, True, True), (JNI_COMMIT, True, False), (JNI_ABORT, False, True)):
                for arch in ARCHES:
                    with self.subTest(kind=kind, arch=arch, mode=mode):
                        h, arr, ref = self.make(arch, cls, items)
                        ptr = h.call(f"get_{name}_array_elements", 0, ref, 0)
                        size = struct.calcsize(fmt)
                        h.mu.mem_write(ptr + size, native(fmt, set_native))     # native code edits elements 1 and 2
                        h.call(f"release_{name}_array_elements", 0, ref, ptr, mode)
                        after = [items[0], *expected, items[3], items[4]] if copies_back else items
                        self.assertEqual(arr.get_py_items(), after)
                        self.assertEqual(h.libc.freed, [ptr - 8] if frees else [])
                        self.assertIs(h.env.get_reference(ref).value, arr)

    def test_release_with_a_null_buffer_does_nothing(self):
        h, arr, ref = self.make(ARCHES[1], IntArray, [1, 2])
        h.call("release_int_array_elements", 0, ref, 0, 0)
        self.assertEqual((arr.get_py_items(), h.libc.freed), ([1, 2], []))

    def test_upper_register_bits_of_mode_are_ignored(self):
        h, arr, ref = self.make(emu_const.ARCH_ARM64, IntArray, [1, 2])
        ptr = h.call("get_int_array_elements", 0, ref, 0)
        h.mu.mem_write(ptr, native("i", [7, 8]))
        h.call("release_int_array_elements", 0, ref, ptr, JNI_COMMIT | (0xDEADBEEF << 32))
        self.assertEqual((arr.get_py_items(), h.libc.freed), ([7, 8], []))      # copied, not freed

    def test_empty_array(self):
        for kind, name, cls, fmt, *_ in SAMPLES:
            with self.subTest(kind=kind):
                h, arr, ref = self.make(ARCHES[1], cls, [])
                ptr = h.call(f"get_{name}_array_elements", 0, ref, IS_COPY)
                self.assertNotEqual(ptr, 0)
                h.call(f"release_{name}_array_elements", 0, ref, ptr, 0)
                self.assertEqual((arr.get_py_items(), h.libc.freed), ([], [ptr - 8]))

    def test_array_module_items_are_written_back_in_their_own_type(self):
        h = Harness(ARCHES[1])
        arr = IntArray(array("i", [1, 2, 3]))
        ref = h.obj_ref(arr)
        ptr = h.call("get_int_array_elements", 0, ref, 0)
        h.mu.mem_write(ptr, native("i", [9, 9, 9]))
        h.call("release_int_array_elements", 0, ref, ptr, 0)
        self.assertEqual((type(arr.get_py_items()), list(arr.get_py_items())), (array, [9, 9, 9]))

    def test_new_array_get_modify_release(self):
        for kind, name, cls, fmt, items, *_ in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h = Harness(arch)
                    ref = h.call(f"new_{name}_array", 0, 5)
                    ptr = h.call(f"get_{name}_array_elements", 0, ref, 0)
                    h.mu.mem_write(ptr, native(fmt, items))
                    h.call(f"release_{name}_array_elements", 0, ref, ptr, 0)
                    self.assertEqual(h.env.get_reference(ref).value.get_py_items(), items)

    def test_an_array_of_another_element_type_is_rejected(self):
        h, arr, ref = self.make(ARCHES[1], CharArray, [1, 2])
        with self.assertRaisesRegex(ValueError, "GetIntArrayElements.*\\[C"):
            h.call("get_int_array_elements", 0, ref, 0)
        with self.assertRaisesRegex(ValueError, "ReleaseShortArrayElements"):
            h.call("release_short_array_elements", 0, ref, 0x1234, 0)


class TestPrimitiveArrayCritical(unittest.TestCase):

    def test_every_element_type(self):
        for kind, name, cls, fmt, items, set_native, expected in SAMPLES:
            for arch in ARCHES:
                with self.subTest(kind=kind, arch=arch):
                    h = Harness(arch)
                    arr = cls(list(items))
                    ref = h.obj_ref(arr)
                    ptr = h.call("get_primitive_array_critical", 0, ref, IS_COPY)
                    self.assertEqual(bytes(h.mu.mem_read(ptr, 5 * struct.calcsize(fmt))), native(fmt, items))
                    h.mu.mem_write(ptr + struct.calcsize(fmt), native(fmt, set_native))
                    h.call("release_primitive_array_critical", 0, ref, ptr, 0)
                    self.assertEqual(arr.get_py_items(), [items[0], *expected, items[3], items[4]])

    def test_byte_arrays_are_unchanged(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h = Harness(arch)
                for arr in (ByteArray(bytearray(b"abcdef")), Array(bytearray(b"abcdef"))):  # incl. what NewByteArray makes
                    ref = h.obj_ref(arr)
                    ptr = h.call("get_primitive_array_critical", 0, ref, 0)
                    self.assertEqual(bytes(h.mu.mem_read(ptr, 6)), b"abcdef")
                    h.mu.mem_write(ptr, b"Q")
                    h.call("release_primitive_array_critical", 0, ref, ptr, 0)
                    self.assertEqual(bytes(arr.get_py_items()), b"Qbcdef")

    def test_an_array_with_unknown_element_type_is_rejected(self):
        h = Harness(ARCHES[1])
        for arr in (Array([1, 2, 3]), ObjectArray([None])):
            with self.subTest(arr=type(arr).__name__):
                with self.assertRaisesRegex(ValueError, "cannot tell the element type"):
                    h.call("get_primitive_array_critical", 0, h.obj_ref(arr), 0)


if __name__ == "__main__":
    unittest.main()
