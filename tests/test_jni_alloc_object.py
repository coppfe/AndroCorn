import unittest

from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.jni.reference import jobject

try:
    from .jni_harness import Harness, ARCHES
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES


class RequiredArgs(metaclass=JavaClassDef, jvm_name='test/alloc/RequiredArgs'):
    """__init__ cannot be called without arguments."""
    py_init_calls = 0
    java_init_calls = 0

    def __init__(self, a, b):
        RequiredArgs.py_init_calls += 1
        self.a = a

    @java_method_def(name='<init>', args_list=['jint'], signature='(I)V', native=False)
    def ctor(self, emu, value):
        RequiredArgs.java_init_calls += 1
        self.value = value


class Defaulted(metaclass=JavaClassDef, jvm_name='test/alloc/Defaulted'):
    """__init__ sets default state, the Java <init> changes it."""
    java_init_calls = 0

    def __init__(self, value=7):
        self.pyobject = value

    @java_method_def(name='<init>', args_list=['jint'], signature='(I)V', native=False)
    def ctor(self, emu, value):
        Defaulted.java_init_calls += 1
        self.pyobject = value


class NoInit(metaclass=JavaClassDef, jvm_name='test/alloc/NoInit'):
    pass


class BrokenInit(metaclass=JavaClassDef, jvm_name='test/alloc/BrokenInit'):
    def __init__(self, x=None):
        raise TypeError("boom from the mock itself")


class TestAllocObject(unittest.TestCase):

    def setUp(self):
        RequiredArgs.py_init_calls = RequiredArgs.java_init_calls = 0
        Defaulted.java_init_calls = 0

    @staticmethod
    def make(arch):
        h = Harness(arch)
        return h, {cls: h.add_class(cls) for cls in (RequiredArgs, Defaulted, NoInit, BrokenInit)}

    def test_returns_a_local_reference_to_a_new_instance(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                ref = h.call("alloc_object", 0, refs[NoInit])
                self.assertNotEqual(ref, 0)
                obj = h.env.get_reference(ref).value
                self.assertIs(type(obj), NoInit)
                # every call allocates a fresh object
                ref2 = h.call("alloc_object", 0, refs[NoInit])
                self.assertIsNot(h.env.get_reference(ref2).value, obj)

    def test_required_init_args_do_not_break_allocation(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                obj = h.env.get_reference(h.call("alloc_object", 0, refs[RequiredArgs])).value
                self.assertIs(type(obj), RequiredArgs)
                self.assertFalse(hasattr(obj, "a"))
                self.assertEqual(RequiredArgs.py_init_calls, 0)

    def test_java_constructor_is_never_run(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                h.call("alloc_object", 0, refs[RequiredArgs])
                h.call("alloc_object", 0, refs[Defaulted])
                self.assertEqual(RequiredArgs.java_init_calls, 0)
                self.assertEqual(Defaulted.java_init_calls, 0)

    def test_python_default_state_is_kept_when_init_needs_no_args(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                obj = h.env.get_reference(h.call("alloc_object", 0, refs[Defaulted])).value
                self.assertEqual(obj.pyobject, 7)

    def test_errors_inside_a_mock_init_are_not_swallowed(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                with self.assertRaisesRegex(TypeError, "boom from the mock itself"):
                    h.call("alloc_object", 0, refs[BrokenInit])

    def test_null_and_non_class_references_are_rejected(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                with self.assertRaises(ValueError):
                    h.call("alloc_object", 0, 0)
                not_a_class = h.obj_ref(NoInit())
                with self.assertRaises(ValueError):
                    h.call("alloc_object", 0, not_a_class)


if __name__ == "__main__":
    unittest.main()
