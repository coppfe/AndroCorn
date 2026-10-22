import struct
import unittest

from androidemu.const import emu_const
from androidemu.java.class_def import JavaClassDef
from androidemu.java.jvm.constants import JAVA_NULL
from androidemu.java.method_def import java_method_def

try:
    from .jni_harness import Harness, ARCHES, MEM_BASE
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES, MEM_BASE

VA_LIST = MEM_BASE + 0x200       # the va_list structure (ARM64) / the argument area (ARM32)
GR_AREA = MEM_BASE + 0x300       # ARM64 register save area

ARGS_SIG = '(IJILjava/lang/String;)I'
ARGS_LIST = ['jint', 'jlong', 'jint', 'jstring']
BIG = 0x0102030405060708         # positive: the plain/va_list readers give ARM64 longs unsigned


class Base(metaclass=JavaClassDef, jvm_name='test/nv/Base'):
    ctor_calls = 0

    def __init__(self):
        self.value = None
        self.seen = None

    @java_method_def(name='<init>', args_list=['jint'], signature='(I)V', native=False)
    def ctor(self, emu, v):
        Base.ctor_calls += 1
        self.value = v

    @java_method_def(name='who', args_list=[], signature='()I', native=False)
    def who(self, emu):
        return 1

    @java_method_def(name='args', args_list=ARGS_LIST, signature=ARGS_SIG, native=False)
    def args(self, emu, *a):
        self.seen = a
        return 0


class Derived(Base, metaclass=JavaClassDef, jvm_name='test/nv/Derived', jvm_super=Base):
    @java_method_def(name='who', args_list=[], signature='()I', native=False)
    def who(self, emu):
        return 2


class Unrelated(metaclass=JavaClassDef, jvm_name='test/nv/Unrelated'):
    @java_method_def(name='other', args_list=[], signature='()V', native=False)
    def other(self, emu):
        pass


class Ret(metaclass=JavaClassDef, jvm_name='test/nv/Ret'):
    retval = None

    @java_method_def(name='get', args_list=[], signature='()I', native=False)
    def get(self, emu):
        return Ret.retval

    @java_method_def(name='nothing', args_list=[], signature='()V', native=False)
    def nothing(self, emu):
        Ret.retval = "called"


KINDS = ("object", "boolean", "byte", "char", "short", "int", "long", "float", "double", "void")
VARIANTS = ("", "_v", "_a")


def make(arch):
    h = Harness(arch)
    refs = {cls: h.add_class(cls) for cls in (Base, Derived, Unrelated, Ret)}
    return h, refs


def mid(cls, name, sig):
    return cls.find_method(name, sig).jvm_id


class TestNonvirtualSemantics(unittest.TestCase):

    def test_the_override_is_not_dispatched(self):
        for variant in VARIANTS:
            for arch in ARCHES:
                with self.subTest(arch=arch, variant=variant):
                    h, refs = make(arch)
                    obj = h.obj_ref(Derived())
                    who = mid(Base, 'who', '()I')
                    nonvirtual = h.call(f"call_nonvirtual_int_method{variant}", 0, obj, refs[Base], who, 0)
                    self.assertEqual(nonvirtual, 1)             # Base.who, although the object is a Derived

    def test_a_virtual_call_with_the_same_id_does_dispatch(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = make(arch)
                obj = h.obj_ref(Derived())
                self.assertEqual(h.call("call_int_method_a", 0, obj, mid(Base, 'who', '()I'), 0), 2)

    def test_the_class_argument_selects_the_implementation(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                h, refs = make(arch)
                obj = h.obj_ref(Derived())
                derived_who = mid(Derived, 'who', '()I')
                self.assertEqual(h.call("call_nonvirtual_int_method_a", 0, obj, refs[Derived], derived_who, 0), 2)
                # an id that comes from a superclass resolves through the class hierarchy
                base_who = mid(Base, 'who', '()I')
                self.assertEqual(h.call("call_nonvirtual_int_method_a", 0, obj, refs[Derived], base_who, 0), 1)

    def test_alloc_object_then_the_constructor(self):
        # the pattern the family exists for
        for variant in VARIANTS:
            for arch in ARCHES:
                with self.subTest(arch=arch, variant=variant):
                    h, refs = make(arch)
                    Base.ctor_calls = 0
                    obj_ref = h.call("alloc_object", 0, refs[Derived])
                    obj = h.env.get_reference(obj_ref).value
                    ctor = mid(Base, '<init>', '(I)V')
                    self.assertEqual(Base.ctor_calls, 0)
                    self.arguments(h, variant, obj_ref, refs[Base], ctor, [('jint', 42)], "call_nonvirtual_void_method")
                    self.assertEqual((obj.value, Base.ctor_calls), (42, 1))

    # --- the three ways of passing arguments --------------------------------------------------
    def arguments(self, h, variant, obj_ref, clazz_ref, method_id, items, name):
        """Calls `name+variant` with the arguments `items` [(jtype, value)] laid out like a compiled caller does."""
        if variant == "_a":
            h.write_jvalues(items)
            return h.call(name + "_a", 0, obj_ref, clazz_ref, method_id, MEM_BASE)
        if variant == "":
            return h.call(name, 0, obj_ref, clazz_ref, method_id, *self.plain_words(h, items))
        va_list = self.write_va_list(h, items)
        return h.call(name + "_v", 0, obj_ref, clazz_ref, method_id, va_list)

    def plain_words(self, h, items):
        """Variadic arguments after (env, obj, clazz, methodID): they start at register 4."""
        if h.arch == emu_const.ARCH_ARM64:
            return [v for _, v in items]               # one register / stack slot each
        words = []
        for t, v in items:
            if t in ('jlong', 'jdouble'):
                if (4 + len(words)) & 1:
                    words.append(0xDEAD)               # padding: 64 bit values start at an even position
                words += [v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF]
            else:
                words.append(v)
        return words

    def write_va_list(self, h, items):
        """Lays out the arguments and returns what the caller passes in the va_list parameter."""
        if h.arch == emu_const.ARCH_ARM32:             # va_list is a 4 byte struct passed by value: the pointer itself
            data = bytearray()
            for t, v in items:
                if t in ('jlong', 'jdouble'):
                    data += b"\0" * ((-len(data)) % 8)
                    data += struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
                else:
                    data += struct.pack("<I", v)
            h.mu.mem_write(VA_LIST, bytes(data))
            return VA_LIST
        gr_offs = -8 * len(items)                      # AAPCS64 va_list, all arguments in the GP save area
        h.mu.mem_write(VA_LIST, struct.pack("<QQQii", VA_LIST + 0x100, GR_AREA + 8 * len(items), VA_LIST + 0x80, gr_offs, 0))
        h.mu.mem_write(GR_AREA, b"".join(struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF) for _, v in items))
        return VA_LIST

    def test_arguments_in_every_form(self):
        for variant in VARIANTS:
            for arch in ARCHES:
                with self.subTest(arch=arch, variant=variant):
                    h, refs = make(arch)
                    obj = Derived()
                    string = object()
                    items = [('jint', 7), ('jlong', BIG), ('jint', 9), ('jstring', h.obj_ref(string))]
                    self.arguments(h, variant, h.obj_ref(obj), refs[Base], mid(Base, 'args', ARGS_SIG), items,
                                   "call_nonvirtual_int_method")
                    self.assertEqual(obj.seen[:3], (7, BIG, 9))
                    self.assertIs(obj.seen[3], string)

    def test_arm32_long_alignment_follows_register_4(self):
        # first variadic argument is a jlong: abs. register 4 is even, no padding word before it
        h, refs = make(emu_const.ARCH_ARM32)
        obj = Derived()
        string = object()
        self.assertEqual(self.plain_words(h, [('jlong', BIG), ('jint', 1)]), [0x05060708, 0x01020304, 1])
        self.assertEqual(self.plain_words(h, [('jint', 7), ('jlong', BIG)]), [7, 0xDEAD, 0x05060708, 0x01020304])
        # and through the real call: (int, long, int, string) = [7, pad, lo, hi, 9, ref]
        items = [('jint', 7), ('jlong', BIG), ('jint', 9), ('jstring', h.obj_ref(string))]
        self.arguments(h, "", h.obj_ref(obj), refs[Base], mid(Base, 'args', ARGS_SIG), items, "call_nonvirtual_int_method")
        self.assertEqual(obj.seen[:3], (7, BIG, 9))


class TestNonvirtualResults(unittest.TestCase):

    def run_kind(self, h, refs, kind, variant, value):
        Ret.retval = value
        return h.call(f"call_nonvirtual_{kind}_method{variant}", 0, h.obj_ref(Ret()), refs[Ret],
                      mid(Ret, 'get', '()I'), 0)

    def test_integral_results(self):
        cases = [("boolean", True, 1), ("boolean", False, 0), ("byte", 5, 5), ("char", 65, 65),
                 ("short", 300, 300), ("int", 1234, 1234)]
        for variant in VARIANTS:
            for arch in ARCHES:
                for kind, value, expected in cases:
                    with self.subTest(arch=arch, variant=variant, kind=kind, value=value):
                        h, refs = make(arch)
                        self.assertEqual(self.run_kind(h, refs, kind, variant, value), expected)

    def test_object_result(self):
        for variant in VARIANTS:
            for arch in ARCHES:
                with self.subTest(arch=arch, variant=variant):
                    h, refs = make(arch)
                    result = Base()       # a Java-style object (the va_list path needs its jvm attributes)
                    ref = self.run_kind(h, refs, "object", variant, result)
                    self.assertIs(h.env.get_reference(ref).value, result)

    def test_long_float_double_results(self):
        for variant in VARIANTS:
            for arch in ARCHES:
                with self.subTest(arch=arch, variant=variant, kind="long"):
                    h, refs = make(arch)
                    r0 = self.run_kind(h, refs, "long", variant, 0x1122334455667788)
                    got = r0 if arch == emu_const.ARCH_ARM64 else (h.emu.registers.v_reg_1 << 32) | r0
                    self.assertEqual(got, 0x1122334455667788)
                with self.subTest(arch=arch, variant=variant, kind="float"):
                    h, refs = make(arch)
                    self.run_kind(h, refs, "float", variant, 1.5)
                    self.assertEqual(h.fp_return_bits(is_double=False), 0x3FC00000)
                with self.subTest(arch=arch, variant=variant, kind="double"):
                    h, refs = make(arch)
                    self.run_kind(h, refs, "double", variant, -2.25)
                    self.assertEqual(h.fp_return_bits(is_double=True),
                                     struct.unpack("<Q", struct.pack("<d", -2.25))[0])

    def test_void_runs_the_method(self):
        for variant in VARIANTS:
            for arch in ARCHES:
                with self.subTest(arch=arch, variant=variant):
                    h, refs = make(arch)
                    Ret.retval = None
                    h.call(f"call_nonvirtual_void_method{variant}", 0, h.obj_ref(Ret()), refs[Ret],
                           mid(Ret, 'nothing', '()V'), 0)
                    self.assertEqual(Ret.retval, "called")

    def test_every_entry_is_implemented(self):
        for arch in ARCHES:
            for kind in KINDS:
                for variant in VARIANTS:
                    with self.subTest(arch=arch, kind=kind, variant=variant):
                        h, refs = make(arch)
                        name = "nothing" if kind == "void" else "get"
                        sig = "()V" if kind == "void" else "()I"
                        Ret.retval = Base() if kind == "object" else 0
                        h.call(f"call_nonvirtual_{kind}_method{variant}", 0, h.obj_ref(Ret()), refs[Ret],
                               mid(Ret, name, sig), 0)


class TestNonvirtualErrors(unittest.TestCase):

    def test_errors(self):
        for variant in VARIANTS:
            for arch in ARCHES:
                with self.subTest(arch=arch, variant=variant):
                    h, refs = make(arch)
                    name = f"call_nonvirtual_int_method{variant}"
                    who = mid(Base, 'who', '()I')
                    obj = h.obj_ref(Derived())
                    with self.assertRaises(ValueError):                  # null object
                        h.call(name, 0, 0, refs[Base], who, 0)
                    with self.assertRaises(ValueError):                  # clazz is not a class
                        h.call(name, 0, obj, h.obj_ref(Base()), who, 0)
                    with self.assertRaisesRegex(RuntimeError, "test/nv/Unrelated"):   # id unknown to that class
                        h.call(name, 0, obj, refs[Unrelated], who, 0)


if __name__ == "__main__":
    unittest.main()
