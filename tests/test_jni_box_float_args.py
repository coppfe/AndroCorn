import struct
import unittest

from androidemu.const import emu_const
from androidemu.java.classes.java.lang.types import Double, Float

try:
    from .jni_harness import Harness, ARCHES
    from . import test_jni_fp_args
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES
    import test_jni_fp_args

FLOAT = struct.unpack("<f", struct.pack("<f", 0.1))[0]
DOUBLE = -1234.5678


class TestBoxedFloatingPointValues(unittest.TestCase):
    """Double.valueOf(double) / Float.valueOf(float) from native code, then <prim>Value(): the round trip must keep the number."""

    forms = test_jni_fp_args.TestEveryCallForm()   # only used for its call builders

    def test_valueof_in_every_call_form(self):
        for form in ("plain", "va_list", "jvalues"):
            for arch in ARCHES:
                for cls, jtype, sig, getter, value in ((Double, 'jdouble', 'D', 'doubleValue', DOUBLE),
                                                       (Float, 'jfloat', 'F', 'floatValue', FLOAT)):
                    with self.subTest(form=form, arch=arch, cls=cls.__name__):
                        h = Harness(arch)
                        cref = h.add_class(cls)
                        value_of = cls.find_method('valueOf', f'({sig})Ljava/lang/{cls.__name__};').jvm_id
                        ref = getattr(self.forms, form)(h, cref, value_of, [(jtype, value)], "call_static_object_method")
                        boxed = h.env.get_reference(ref).value
                        self.assertIs(type(boxed), cls)
                        self.assertEqual(boxed.pyobject, value)
                        self.assertIsInstance(boxed.pyobject, float)

                        # and back out: <prim>Value() returns it in the floating point return register
                        getter_id = cls.find_method(getter, f'(){sig}').jvm_id
                        kind = "double" if cls is Double else "float"
                        h.call(f"call_{kind}_method_a", 0, h.obj_ref(boxed), getter_id, 0)
                        raw = h.fp_return_bits(is_double=(cls is Double))
                        packed = struct.pack("<d" if cls is Double else "<f", value)
                        self.assertEqual(raw, struct.unpack("<Q" if cls is Double else "<I", packed)[0])


if __name__ == "__main__":
    unittest.main()
