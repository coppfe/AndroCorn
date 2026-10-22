import unittest

from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.classes.java.lang.array import ObjectArray
from androidemu.java.classes.java.lang.clazz import Class
from androidemu.java.classes.java.lang.string import String
from androidemu.java.classes.java.lang.types import (
    Boolean, Byte, Character, Double, Float, Integer, Long, Short,
)

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE

NAME_PTR = MEM_BASE + 0x400
SIG_PTR = MEM_BASE + 0x440

# box class, descriptor of its primitive, the name Java gives to the primitive's Class
PRIMITIVES = [
    (Boolean, "Z", "boolean"), (Byte, "B", "byte"), (Character, "C", "char"), (Short, "S", "short"),
    (Integer, "I", "int"), (Long, "J", "long"), (Float, "F", "float"), (Double, "D", "double"),
]


class Holder(metaclass=JavaClassDef, jvm_name='test/prim/Holder'):
    @java_method_def(name='foo', args_list=['jint', 'jobject'], signature='(ILjava/lang/Integer;)V', native=False)
    def foo(self, emu, a, b):
        pass

    @java_method_def(name='bar', args_list=['jdouble', 'jlong'], signature='(DJ)V', native=False)
    def bar(self, emu, a, b):
        pass


class TestTypeFields(unittest.TestCase):

    def get_type(self, h, box):
        cref = h.class_ref(box)
        h.mu.mem_write(NAME_PTR, b"TYPE\0")
        h.mu.mem_write(SIG_PTR, b"Ljava/lang/Class;\0")
        fid = h.call("get_static_field_id", 0, cref, NAME_PTR, SIG_PTR)
        ref = h.call("get_static_object_field", 0, cref, fid)
        return h.env.get_reference(ref).value

    def test_every_box_class_has_the_type_of_its_primitive(self):
        for arch in ARCHES:
            for box, desc, name in PRIMITIVES:
                with self.subTest(arch=arch, box=box.__name__):
                    h = Harness(arch)
                    h.add_class(box)
                    prim = self.get_type(h, box)
                    self.assertIs(prim, Class.primitive(desc))
                    self.assertEqual(prim.get_jni_descriptor(), desc)
                    self.assertEqual(prim.getName(None).get_py_string(), name)
                    self.assertEqual(prim.getCanonicalName(None).get_py_string(), name)
                    self.assertTrue(prim.isPrimitive(None))

    def test_there_is_one_class_object_per_primitive(self):
        h = Harness(ARCHES[1])
        h.add_class(Integer)
        self.assertIs(self.get_type(h, Integer), self.get_type(h, Integer))
        self.assertIsNot(Class.primitive("I"), Class.primitive("J"))

    def test_it_is_not_the_box_class(self):
        # Integer.TYPE is int.class, not Integer.class
        h = Harness(ARCHES[1])
        h.add_class(Integer)
        self.assertIsNot(self.get_type(h, Integer), Integer.class_object)
        self.assertEqual(Integer.class_object.getName(None).get_py_string(), "java.lang.Integer")

    def test_ordinary_classes_are_unchanged(self):
        h = Harness(ARCHES[1])
        h.add_class(Holder)
        cls = Holder.class_object
        self.assertEqual(cls.getName(None).get_py_string(), "test.prim.Holder")
        self.assertEqual(cls.getCanonicalName(None).get_py_string(), "test.prim.Holder")
        self.assertFalse(cls.isPrimitive(None))

    def test_unknown_descriptor_is_rejected(self):
        for bad in ("X", "Ljava/lang/Integer;", "", "[I"):
            with self.subTest(descriptor=bad):
                with self.assertRaises(ValueError):
                    Class.primitive(bad)

    def test_primitive_class_has_no_loader_and_no_members(self):
        prim = Class.primitive("I")
        self.assertIsNone(prim.getClassLoader(None))
        self.assertEqual(len(prim.getDeclaredMethods(None)), 0)
        self.assertEqual(len(prim.getDeclaredFields(None)), 0)


class TestAsReflectionArguments(unittest.TestCase):

    def test_get_declared_method_with_primitive_parameter_types(self):
        h = Harness(ARCHES[1])
        h.add_class(Holder)
        h.add_class(Integer)
        # Holder.class.getDeclaredMethod("foo", int.class, Integer.class)
        params = ObjectArray([Class.primitive("I"), Integer.class_object])
        method = Holder.class_object.getDeclaredMethod(None, String("foo"), params)
        self.assertEqual(method.getName(None).get_py_string(), "foo")
        # Holder.class.getDeclaredMethod("bar", double.class, long.class)
        params = ObjectArray([Class.primitive("D"), Class.primitive("J")])
        method = Holder.class_object.getDeclaredMethod(None, String("bar"), params)
        self.assertEqual(method.getName(None).get_py_string(), "bar")


if __name__ == "__main__":
    unittest.main()
