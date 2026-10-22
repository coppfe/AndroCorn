import struct
import unittest
from types import SimpleNamespace

from androidemu.const import emu_const
from androidemu.core.emulator import Emulator
from androidemu.java.classloader import JavaClassLoader
from androidemu.java.classes.java.lang.types import (
    Boolean, Byte, Character, Double, Float, Integer, Long, Short,
)

try:
    from .jni_harness import Harness, ARCHES
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES

BOXES = (Boolean, Byte, Character, Double, Float, Integer, Long, Short)


def f32(v):
    return struct.unpack("<I", struct.pack("<f", v))[0]


def f64(v):
    return struct.unpack("<Q", struct.pack("<d", v))[0]


# cls, primitive JNI type, getter (name, JNI call kind), constructor/valueOf argument, how the getter result looks
CASES = [
    (Boolean,   "jboolean", "Z", "booleanValue", "boolean", 1,      "bool"),
    (Byte,      "jbyte",    "B", "byteValue",    "byte",    -5,     0xFB),
    (Character, "jchar",    "C", "charValue",    "char",    0xFFFE, 0xFFFE),
    (Short,     "jshort",   "S", "shortValue",   "short",   -5,     0xFFFB),
    (Integer,   "jint",     "I", "intValue",     "int",     -5,     0xFFFFFFFB),
    (Long,      "jlong",    "J", "longValue",    "long",    -(1 << 40), "long"),
    (Float,     "jfloat",   "F", "floatValue",   "float",   1.5,    "float"),
    (Double,    "jdouble",  "D", "doubleValue",  "double",  -2.25,  "double"),
]


class TestBoxClasses(unittest.TestCase):

    def make(self, arch):
        h = Harness(arch)
        for cls in BOXES:
            h.add_class(cls)
        return h

    def check_result(self, h, r0, kind, value, expected):
        if expected == "float":
            self.assertEqual(h.fp_return_bits(is_double=False), f32(value))
        elif expected == "double":
            self.assertEqual(h.fp_return_bits(is_double=True), f64(value))
        elif expected == "long":
            got = r0 if h.arch == emu_const.ARCH_ARM64 else (h.emu.registers.v_reg_1 << 32) | r0
            self.assertEqual(got, value & 0xFFFFFFFFFFFFFFFF)
        elif expected == "bool":
            self.assertEqual(r0, 1)
        else:
            self.assertEqual(r0, expected)

    def test_constructor_valueof_and_getter(self):
        for cls, jtype, sig, getter, kind, value, expected in CASES:
            for arch in ARCHES:
                with self.subTest(cls=cls.__name__, arch=arch):
                    h = self.make(arch)
                    cref = h.class_ref(cls)

                    # new Box(value)
                    h.write_jvalues([(jtype, value)])
                    ctor = cls.find_method('<init>', f'({sig})V').jvm_id
                    obj_ref = h.call("new_object_a", 0, cref, ctor, 0x10000)
                    obj = h.env.get_reference(obj_ref).value
                    self.assertIs(type(obj), cls)
                    self.assertEqual(obj.pyobject, value if kind != "bool" else 1)

                    # Box.valueOf(value)
                    h.write_jvalues([(jtype, value)])
                    value_of = cls.find_method('valueOf', f'({sig})Ljava/lang/{cls.__name__};').jvm_id
                    ref = h.call("call_static_object_method_a", 0, cref, value_of, 0x10000)
                    boxed = h.env.get_reference(ref).value
                    self.assertIs(type(boxed), cls)
                    self.assertEqual(boxed.pyobject, obj.pyobject)

                    # box.<prim>Value()
                    getter_id = cls.find_method(getter, f'(){sig}').jvm_id
                    r0 = h.call(f"call_{kind}_method_a", 0, obj_ref, getter_id, 0)
                    self.check_result(h, r0, kind, value, expected)

    def test_get_class_returns_the_class_object(self):
        for cls, jtype, sig, getter, kind, value, expected in CASES:
            with self.subTest(cls=cls.__name__):
                h = self.make(emu_const.ARCH_ARM64)
                obj_ref = h.obj_ref(cls(value))
                get_class = cls.find_method('getClass', '()Ljava/lang/Class;').jvm_id
                ref = h.call("call_object_method_a", 0, obj_ref, get_class, 0)
                self.assertIs(h.env.get_reference(ref).value, cls.class_object)

    def test_python_defaults_and_repr(self):
        self.assertEqual((Short().pyobject, Byte().pyobject, Character().pyobject), (0, 0, 0))
        self.assertEqual((Double().pyobject, Float().pyobject), (0.0, 0.0))
        self.assertEqual(repr(Double(1.5)), "1.5")
        self.assertEqual(repr(Short(7)), "7")


class TestRegistration(unittest.TestCase):

    def test_the_emulator_registers_every_box_class(self):
        owner = SimpleNamespace(java_classloader=JavaClassLoader())
        Emulator._init_base_java_classes(owner)
        for cls in BOXES:
            with self.subTest(cls=cls.__name__):
                self.assertIs(owner.java_classloader.find_class_by_name(cls.jvm_name), cls)


if __name__ == "__main__":
    unittest.main()
