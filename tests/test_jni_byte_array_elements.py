import unittest

from androidemu.java.classes.java.lang.array import ByteArray
from androidemu.java.jni.constants import JNI_ABORT, JNI_COMMIT

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE

IS_COPY = MEM_BASE + 0x500


class TestByteArrayElements(unittest.TestCase):

    def setup(self, arch, data=b"abcdef"):
        h = Harness(arch)
        arr = ByteArray(bytearray(data))
        return h, arr, h.obj_ref(arr)

    def test_the_buffer_holds_the_bytes(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch)
                ptr = h.call("get_byte_array_elements", 0, ref, 0)
                self.assertEqual(bytes(h.mu.mem_read(ptr, 6)), b"abcdef")

    def test_is_copy_pointer_is_accepted_and_set(self):
        # GetByteArrayElements(env, arr, &isCopy) used to raise NotImplementedError
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch)
                h.mu.mem_write(IS_COPY, b"\x00")
                ptr = h.call("get_byte_array_elements", 0, ref, IS_COPY)
                self.assertEqual(bytes(h.mu.mem_read(IS_COPY, 1)), b"\x01")      # JNI_TRUE: it is a copy
                self.assertEqual(bytes(h.mu.mem_read(ptr, 6)), b"abcdef")

    def test_empty_array(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch, b"")
                self.assertNotEqual(h.call("get_byte_array_elements", 0, ref, IS_COPY), 0)

    def test_release_modes(self):
        for mode, copies_back, frees in ((0, True, True), (JNI_COMMIT, True, False), (JNI_ABORT, False, True)):
            for arch in ARCHES:
                with self.subTest(arch=arch, mode=mode):
                    h, arr, ref = self.setup(arch)
                    ptr = h.call("get_byte_array_elements", 0, ref, 0)
                    h.mu.mem_write(ptr, b"XYZ")                  # native code modifies the buffer
                    h.call("release_byte_array_elements", 0, ref, ptr, mode)
                    self.assertEqual(bytes(arr.get_py_items()), b"XYZdef" if copies_back else b"abcdef")
                    self.assertEqual(h.libc.freed, [ptr - 8] if frees else [])

    def test_primitive_array_critical_on_a_byte_array(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, arr, ref = self.setup(arch)
                ptr = h.call("get_primitive_array_critical", 0, ref, IS_COPY)
                h.mu.mem_write(ptr, b"Q")
                h.call("release_primitive_array_critical", 0, ref, ptr, 0)
                self.assertEqual(bytes(arr.get_py_items()), b"Qbcdef")


if __name__ == "__main__":
    unittest.main()
