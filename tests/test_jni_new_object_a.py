import unittest

from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def

try:
    from .jni_harness import Harness, ARCHES
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES


class Point(metaclass=JavaClassDef, jvm_name='test/newa/Point'):
    inits = 0

    def __init__(self):
        self.args = None

    @java_method_def(name='<init>', args_list=['jint', 'jlong', 'jdouble', 'jstring'],
                     signature='(IJDLjava/lang/String;)V', native=False)
    def ctor(self, emu, i, j, d, s):
        Point.inits += 1
        self.args = (i, j, d, s)

    @java_method_def(name='<init>', args_list=[], signature='()V', native=False)
    def ctor_empty(self, emu):
        Point.inits += 1
        self.args = ()

    @java_method_def(name='notACtor', args_list=[], signature='()V', native=False)
    def not_a_ctor(self, emu):
        pass


class TestNewObjectA(unittest.TestCase):

    def setUp(self):
        Point.inits = 0

    def test_constructor_gets_the_decoded_jvalue_array(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                Point.inits = 0
                h = Harness(arch)
                cref = h.add_class(Point)
                string = object()
                h.write_jvalues([('jint', -5), ('jlong', -(1 << 40)), ('jdouble', 2.5), ('jstring', h.obj_ref(string))])
                mid = Point.find_method('<init>', '(IJDLjava/lang/String;)V').jvm_id
                ref = h.call("new_object_a", 0, cref, mid, 0x10000)
                obj = h.env.get_reference(ref).value
                self.assertIs(type(obj), Point)
                self.assertEqual(obj.args[:3], (-5, -(1 << 40), 2.5))
                self.assertIs(obj.args[3], string)
                self.assertEqual(Point.inits, 1)

    def test_no_argument_constructor_with_a_null_jvalue_pointer(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h = Harness(arch)
                cref = h.add_class(Point)
                mid = Point.find_method('<init>', '()V').jvm_id
                ref = h.call("new_object_a", 0, cref, mid, 0)
                self.assertEqual(h.env.get_reference(ref).value.args, ())

    def test_each_call_creates_a_new_object(self):
        h = Harness(ARCHES[1])
        cref = h.add_class(Point)
        mid = Point.find_method('<init>', '()V').jvm_id
        a = h.env.get_reference(h.call("new_object_a", 0, cref, mid, 0)).value
        b = h.env.get_reference(h.call("new_object_a", 0, cref, mid, 0)).value
        self.assertIsNot(a, b)

    def test_errors(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h = Harness(arch)
                cref = h.add_class(Point)
                with self.assertRaises(ValueError):      # not a class
                    h.call("new_object_a", 0, h.obj_ref(Point()), 1, 0)
                with self.assertRaisesRegex(ValueError, "constructor"):
                    h.call("new_object_a", 0, cref, Point.find_method('notACtor', '()V').jvm_id, 0)


if __name__ == "__main__":
    unittest.main()
