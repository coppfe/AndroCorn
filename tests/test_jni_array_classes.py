import unittest
from types import SimpleNamespace

from androidemu.core.emulator import Emulator
from androidemu.java.classloader import JavaClassLoader
from androidemu.java.classes.java.lang.array import (
    Array, BooleanArray, ByteArray, CharArray, DoubleArray, FloatArray, IntArray, LongArray, ObjectArray, ShortArray,
)

try:
    from .jni_harness import Harness, ARCHES
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES

# class, jvm name, JNI kind letter
PRIMITIVE_ARRAYS = [
    (BooleanArray, "[Z", "Z"), (ByteArray, "[B", "B"), (CharArray, "[C", "C"), (ShortArray, "[S", "S"),
    (IntArray, "[I", "I"), (LongArray, "[J", "J"), (FloatArray, "[F", "F"), (DoubleArray, "[D", "D"),
]


class TestPrimitiveArrayClasses(unittest.TestCase):

    def test_names_kinds_and_inheritance(self):
        for cls, jvm_name, kind in PRIMITIVE_ARRAYS:
            with self.subTest(cls=cls.__name__):
                self.assertEqual(cls.jvm_name, jvm_name)
                self.assertEqual(cls.jni_kind, kind)
                self.assertTrue(issubclass(cls, Array))

    def test_arrays_without_a_known_element_type(self):
        self.assertIsNone(Array.jni_kind)
        self.assertIsNone(ObjectArray.jni_kind)

    def test_they_behave_like_the_existing_arrays(self):
        for cls, jvm_name, kind in PRIMITIVE_ARRAYS:
            with self.subTest(cls=cls.__name__):
                arr = cls([1, 2, 3])
                self.assertEqual((len(arr), arr[1], arr.get_py_items()), (3, 2, [1, 2, 3]))
                arr[1] = 9
                self.assertEqual(arr.get_py_items(), [1, 9, 3])

    def test_the_emulator_registers_them(self):
        owner = SimpleNamespace(java_classloader=JavaClassLoader())
        Emulator._init_base_java_classes(owner)
        for cls, jvm_name, kind in PRIMITIVE_ARRAYS:
            with self.subTest(cls=cls.__name__):
                self.assertIs(owner.java_classloader.find_class_by_name(jvm_name), cls)

    def test_get_class_and_its_name(self):
        for cls, jvm_name, kind in PRIMITIVE_ARRAYS:
            with self.subTest(cls=cls.__name__):
                Harness(ARCHES[1])
                self.assertEqual(cls.class_object.getName(None).get_py_string(), jvm_name)


if __name__ == "__main__":
    unittest.main()
