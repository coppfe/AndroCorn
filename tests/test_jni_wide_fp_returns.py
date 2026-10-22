import struct
import unittest

from androidemu.const import emu_const
from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.jvm.constants import JAVA_NULL
from androidemu.java.method_def import java_method_def

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE

NAME_PTR = MEM_BASE + 0x400
SIG_PTR = MEM_BASE + 0x440

# Instance side: every method returns Holder.retval, the fields are plain attributes of the object.
FIELDS = [
    JavaFieldDef('lf', 'J', False),
    JavaFieldDef('ff', 'F', False),
    JavaFieldDef('df', 'D', False),
]

# Static side: the static value of a field is JavaFieldDef.static_value, changed per test.
STATIC_FIELDS = {
    'J': JavaFieldDef('slf', 'J', True, 0),
    'F': JavaFieldDef('sff', 'F', True, 0.0),
    'D': JavaFieldDef('sdf', 'D', True, 0.0),
}


class Holder(metaclass=JavaClassDef, jvm_name='test/wide/Holder', jvm_fields=FIELDS):
    retval = None

    @java_method_def(name='getJ', args_list=[], signature='()J', native=False)
    def get_j(self, emu):
        return Holder.retval

    @java_method_def(name='getF', args_list=[], signature='()F', native=False)
    def get_f(self, emu):
        return Holder.retval

    @java_method_def(name='getD', args_list=[], signature='()D', native=False)
    def get_d(self, emu):
        return Holder.retval

    @java_method_def(name='getI', args_list=[], signature='()I', native=False)
    def get_i(self, emu):
        return Holder.retval

    @java_method_def(name='getObj', args_list=[], signature='()Ljava/lang/Object;', native=False)
    def get_obj(self, emu):
        return Holder.retval

    @java_method_def(name='nothing', args_list=[], signature='()V', native=False)
    def nothing(self, emu):
        pass


class StaticHolder(metaclass=JavaClassDef, jvm_name='test/wide/StaticHolder', jvm_fields=list(STATIC_FIELDS.values())):
    retval = None

    @staticmethod
    @java_method_def(name='getJ', args_list=[], signature='()J', native=False)
    def get_j(emu):
        return StaticHolder.retval

    @staticmethod
    @java_method_def(name='getF', args_list=[], signature='()F', native=False)
    def get_f(emu):
        return StaticHolder.retval

    @staticmethod
    @java_method_def(name='getD', args_list=[], signature='()D', native=False)
    def get_d(emu):
        return StaticHolder.retval

    @staticmethod
    @java_method_def(name='getI', args_list=[], signature='()I', native=False)
    def get_i(emu):
        return StaticHolder.retval

    @staticmethod
    @java_method_def(name='getObj', args_list=[], signature='()Ljava/lang/Object;', native=False)
    def get_obj(emu):
        return StaticHolder.retval


LONG_VALUES = (0x1122334455667788, -2, 0, (1 << 63) - 1, -(1 << 63))
FLOAT_CASES = ((1.5, 0x3FC00000), (-2.0, 0xC0000000), (0.0, 0), (2, 0x40000000),
               (1e40, 0x7F800000), (-1e40, 0xFF800000))
DOUBLE_VALUES = (-2.25, 1e300, 0.1, 3, 0.0)


def double_bits(v):
    return struct.unpack("<Q", struct.pack("<d", float(v)))[0]


class Base(unittest.TestCase):

    def setUp(self):
        Holder.retval = StaticHolder.retval = None

    @staticmethod
    def make(arch):
        h = Harness(arch)
        h.add_class(Holder)
        h.add_class(StaticHolder)
        return h

    def read_long(self, h, r0):
        if h.arch == emu_const.ARCH_ARM64:
            return r0
        return (h.emu.registers.v_reg_1 << 32) | r0

    def check_result(self, h, kind, r0, value, bits=None):
        if kind == "J":
            self.assertEqual(self.read_long(h, r0), value & 0xFFFFFFFFFFFFFFFF)
        elif kind == "F":
            self.assertEqual(h.fp_return_bits(is_double=False), bits)
        else:
            self.assertEqual(h.fp_return_bits(is_double=True), double_bits(value))


class TestCallMethods(Base):
    """Call<T>Method (variadic) and Call<T>MethodV, instance and static, long/float/double."""

    FUNCS = {"J": "long", "F": "float", "D": "double"}
    METHOD = {"J": ("getJ", "()J"), "F": ("getF", "()F"), "D": ("getD", "()D")}

    def invoke(self, h, kind, variant, static, value):
        name, sig = self.METHOD[kind]
        fname = f"call_{'static_' if static else ''}{self.FUNCS[kind]}_method{'_v' if variant == 'v' else ''}"
        if static:
            StaticHolder.retval = value
            target, mid = h.class_ref(StaticHolder), StaticHolder.find_method(name, sig).jvm_id
        else:
            Holder.retval = value
            target, mid = h.obj_ref(Holder()), Holder.find_method(name, sig).jvm_id
        return h.call(fname, 0, target, mid, 0)

    def cases(self, kind):
        if kind == "J":
            return [(v, None) for v in LONG_VALUES + (None,)]
        if kind == "F":
            return list(FLOAT_CASES) + [(None, 0)]
        return [(v, None) for v in DOUBLE_VALUES + (None,)]

    def test_all_paths(self):
        for variant in ("plain", "v"):
            for static in (False, True):
                for kind in ("J", "F", "D"):
                    for arch in ARCHES:
                        for value, bits in self.cases(kind):
                            with self.subTest(variant=variant, static=static, kind=kind, arch=arch, value=value):
                                h = self.make(arch)
                                r0 = self.invoke(h, kind, variant, static, value)
                                self.check_result(h, kind, r0, 0 if value is None else value, bits)

    def test_int_object_and_void_results_are_unchanged(self):
        for variant in ("plain", "v"):
            for static in (False, True):
                for arch in ARCHES:
                    with self.subTest(variant=variant, static=static, arch=arch):
                        h = self.make(arch)
                        suffix = "_v" if variant == "v" else ""
                        pre = "call_static_" if static else "call_"
                        holder = StaticHolder if static else Holder
                        target = h.class_ref(StaticHolder) if static else h.obj_ref(Holder())

                        holder.retval = 1234
                        mid = holder.find_method("getI", "()I").jvm_id
                        self.assertEqual(h.call(f"{pre}int_method{suffix}", 0, target, mid, 0), 1234)

                        result = Holder()   # a Java-style object: the _v path needs its jvm attributes
                        holder.retval = result
                        mid = holder.find_method("getObj", "()Ljava/lang/Object;").jvm_id
                        ref = h.call(f"{pre}object_method{suffix}", 0, target, mid, 0)
                        self.assertIs(h.env.get_reference(ref).value, result)


class TestFieldGetters(Base):

    def field_id(self, h, static, name, sig):
        h.mu.mem_write(NAME_PTR, name.encode() + b"\0")
        h.mu.mem_write(SIG_PTR, sig.encode() + b"\0")
        if static:
            return h.call("get_static_field_id", 0, h.class_ref(StaticHolder), NAME_PTR, SIG_PTR)
        return h.call("get_field_id", 0, h.class_ref(Holder), NAME_PTR, SIG_PTR)

    def test_instance_fields(self):
        names = {"J": ("lf", "getlong", "get_long_field"), "F": ("ff", "getfloat", "get_float_field"),
                 "D": ("df", "getdouble", "get_double_field")}
        sigs = {"J": "J", "F": "F", "D": "D"}
        cases = {"J": [(v, None) for v in LONG_VALUES], "F": list(FLOAT_CASES), "D": [(v, None) for v in DOUBLE_VALUES]}
        for kind, (attr, _, getter) in names.items():
            for arch in ARCHES:
                for value, bits in cases[kind]:
                    with self.subTest(kind=kind, arch=arch, value=value):
                        h = self.make(arch)
                        obj = Holder()
                        setattr(obj, attr, value)
                        fid = self.field_id(h, False, attr, sigs[kind])
                        r0 = h.call(getter, 0, h.obj_ref(obj), fid)
                        self.check_result(h, kind, r0, value, bits)

    def test_static_fields(self):
        names = {"J": ("slf", "get_static_long_field"), "F": ("sff", "get_static_float_field"),
                 "D": ("sdf", "get_static_double_field")}
        cases = {"J": [(v, None) for v in LONG_VALUES], "F": list(FLOAT_CASES), "D": [(v, None) for v in DOUBLE_VALUES]}
        for kind, (fname, getter) in names.items():
            for arch in ARCHES:
                for value, bits in cases[kind]:
                    with self.subTest(kind=kind, arch=arch, value=value):
                        h = self.make(arch)
                        STATIC_FIELDS[kind].static_value = value
                        fid = self.field_id(h, True, fname, kind)
                        r0 = h.call(getter, 0, h.class_ref(StaticHolder), fid)
                        self.check_result(h, kind, r0, value, bits)


if __name__ == "__main__":
    unittest.main()
