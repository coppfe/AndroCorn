import struct
import unittest

from androidemu.const import emu_const
from androidemu.core.registers import RegistersMapping
from androidemu.java.class_def import JavaClassDef
from androidemu.java.jvm.constants import JAVA_NULL
from androidemu.java.method_def import java_method_def

try:
    from .jni_harness import Harness, ARCHES
except ImportError:  # run as a plain script
    from jni_harness import Harness, ARCHES

ALL_ARGS_LIST = ['jboolean', 'jbyte', 'jchar', 'jshort', 'jint', 'jlong', 'jfloat', 'jdouble', 'jobject', 'jstring']
ALL_ARGS_SIG = '(ZBCSIJFDLjava/lang/Object;Ljava/lang/String;)V'


class Target(metaclass=JavaClassDef, jvm_name='test/calla/Target'):
    seen = None        # arguments of the last call
    retval = None      # what the mocked methods return

    def __init__(self):
        self.value = None

    @java_method_def(name='<init>', args_list=['jint'], signature='(I)V', native=False)
    def ctor(self, emu, value):
        self.value = value

    @java_method_def(name='allArgs', args_list=ALL_ARGS_LIST, signature=ALL_ARGS_SIG, native=False)
    def all_args(self, emu, *args):
        Target.seen = args

    @java_method_def(name='get', args_list=[], signature='()I', native=False)
    def get(self, emu):
        return Target.retval

    @java_method_def(name='twoLongs', args_list=['jlong', 'jint'], signature='(JI)J', native=False)
    def two_longs(self, emu, a, b):
        return a + b


class SubTarget(Target, metaclass=JavaClassDef, jvm_name='test/calla/SubTarget', jvm_super=Target):
    @java_method_def(name='get', args_list=[], signature='()I', native=False)
    def get(self, emu):
        return 1000 + Target.retval


class StaticTarget(metaclass=JavaClassDef, jvm_name='test/calla/StaticTarget'):
    seen = None
    retval = None

    @staticmethod
    @java_method_def(name='allArgs', args_list=ALL_ARGS_LIST, signature=ALL_ARGS_SIG, native=False)
    def all_args(emu, *args):
        StaticTarget.seen = args

    @staticmethod
    @java_method_def(name='get', args_list=[], signature='()I', native=False)
    def get(emu):
        return StaticTarget.retval

    @staticmethod
    @java_method_def(name='badArg', args_list=['jwhatever'], signature='(I)V', native=False)
    def bad_arg(emu, a):
        pass


RETURN_KINDS = ("object", "boolean", "byte", "char", "short", "int", "long", "float", "double", "void")


class Base(unittest.TestCase):

    def setUp(self):
        Target.seen = Target.retval = None
        StaticTarget.seen = StaticTarget.retval = None

    @staticmethod
    def make(arch):
        h = Harness(arch)
        refs = {cls: h.add_class(cls) for cls in (Target, SubTarget, StaticTarget)}
        return h, refs

    @staticmethod
    def mid(pyclazz, name, sig):
        return pyclazz.find_method(name, sig).jvm_id

    def each_arch(self):
        return ARCHES


class TestArgumentsDecoding(Base):
    """All ten argument kinds, with garbage in the unused bytes of every jvalue slot."""

    def run_all_args(self, h, call_name, receiver_ref, method_id, obj, string):
        h.write_jvalues([
            ('jboolean', 1), ('jbyte', -5), ('jchar', 0xFFFE), ('jshort', -2), ('jint', -123456),
            ('jlong', -(1 << 40) - 3), ('jfloat', 1.5), ('jdouble', -2.25),
            ('jobject', obj), ('jstring', string),
        ])
        h.call(call_name, 0, receiver_ref, method_id, 0x10000)

    def check(self, seen, obj, string):
        z, b, c, s, i, j, f, d, o, st = seen
        self.assertEqual((z, b, c, s, i), (1, -5, 0xFFFE, -2, -123456))
        self.assertEqual(j, -(1 << 40) - 3)
        self.assertEqual((f, d), (1.5, -2.25))
        self.assertIs(o, obj)
        self.assertIs(st, string)

    def test_instance_method(self):
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                target, obj, string = Target(), object(), object()
                self.run_all_args(h, "call_void_method_a", h.obj_ref(target),
                                  self.mid(Target, 'allArgs', ALL_ARGS_SIG), h.obj_ref(obj), h.obj_ref(string))
                self.check(Target.seen, obj, string)

    def test_static_method(self):
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                obj, string = object(), object()
                self.run_all_args(h, "call_static_void_method_a", refs[StaticTarget],
                                  self.mid(StaticTarget, 'allArgs', ALL_ARGS_SIG), h.obj_ref(obj), h.obj_ref(string))
                self.check(StaticTarget.seen, obj, string)

    def test_garbage_in_unused_bytes_is_ignored(self):
        # a zero jboolean/jint/jobject with 0xA5 garbage around it must still decode as zero
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                h.write_jvalues([
                    ('jboolean', 0), ('jbyte', 0), ('jchar', 0), ('jshort', 0), ('jint', 0),
                    ('jlong', 0), ('jfloat', 0.0), ('jdouble', 0.0), ('jobject', 0), ('jstring', 0),
                ])
                h.call("call_static_void_method_a", 0, refs[StaticTarget],
                       self.mid(StaticTarget, 'allArgs', ALL_ARGS_SIG), 0x10000)
                self.assertEqual(StaticTarget.seen[:8], (0, 0, 0, 0, 0, 0, 0.0, 0.0))
                self.assertEqual(StaticTarget.seen[8:], (JAVA_NULL, JAVA_NULL))

    def test_null_jvalue_pointer_for_a_method_without_arguments(self):
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                StaticTarget.retval = 11
                res = h.call("call_static_int_method_a", 0, refs[StaticTarget],
                             self.mid(StaticTarget, 'get', '()I'), 0)
                self.assertEqual(res, 11)

    def test_unsupported_arg_type_fails_loudly(self):
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                h.write_jvalues([('jint', 1)])
                with self.assertRaisesRegex(ValueError, "jwhatever"):
                    h.call("call_static_void_method_a", 0, refs[StaticTarget],
                           self.mid(StaticTarget, 'badArg', '(I)V'), 0x10000)


class TestReturnValues(Base):

    def get_call(self, h, refs, kind, static):
        """Returns a function calling the `get` method through Call[Static]<kind>MethodA."""
        if static:
            name = f"call_static_{kind}_method_a"
            args = (0, refs[StaticTarget], self.mid(StaticTarget, 'get', '()I'), 0)
            holder = StaticTarget
        else:
            name = f"call_{kind}_method_a"
            args = (0, h.obj_ref(Target()), self.mid(Target, 'get', '()I'), 0)
            holder = Target
        return holder, (lambda: h.call(name, *args))

    def test_integral_kinds_are_masked_to_their_width(self):
        cases = [
            ("boolean", True, 1), ("boolean", False, 0), ("boolean", 5, 1),
            ("byte", -1, 0xFF), ("byte", 0x1FF, 0xFF),
            ("char", 65, 65), ("char", 0x1FFFF, 0xFFFF),
            ("short", -2, 0xFFFE),
            ("int", -1, 0xFFFFFFFF), ("int", 1 << 31, 1 << 31), ("int", 0x1FFFFFFFF, 0xFFFFFFFF),
            ("int", None, 0), ("boolean", None, 0),
        ]
        for static in (False, True):
            for arch in self.each_arch():
                for kind, value, expected in cases:
                    with self.subTest(arch=arch, static=static, kind=kind, value=value):
                        h, refs = self.make(arch)
                        holder, call = self.get_call(h, refs, kind, static)
                        holder.retval = value
                        self.assertEqual(call(), expected)

    def test_long(self):
        for static in (False, True):
            for arch in self.each_arch():
                for value in (0x1122334455667788, -2, 0, None):
                    with self.subTest(arch=arch, static=static, value=value):
                        h, refs = self.make(arch)
                        holder, call = self.get_call(h, refs, "long", static)
                        holder.retval = value
                        r0 = call()
                        iv = (value or 0) & 0xFFFFFFFFFFFFFFFF
                        if arch == emu_const.ARCH_ARM64:
                            self.assertEqual(r0, iv)
                        else:
                            self.assertEqual((h.emu.registers.v_reg_1 << 32) | r0, iv)

    def test_float(self):
        cases = [
            (1.5, 0x3FC00000), (-2.0, 0xC0000000), (2, 0x40000000), (None, 0),
            (1e40, 0x7F800000), (-1e40, 0xFF800000),                          # out of float range -> +-inf
            (float('inf'), 0x7F800000),
        ]
        for static in (False, True):
            for arch in self.each_arch():
                for value, bits in cases:
                    with self.subTest(arch=arch, static=static, value=value):
                        h, refs = self.make(arch)
                        holder, call = self.get_call(h, refs, "float", static)
                        holder.retval = value
                        call()
                        self.assertEqual(h.fp_return_bits(is_double=False), bits)

    def test_double(self):
        for static in (False, True):
            for arch in self.each_arch():
                for value in (-2.25, 1e300, 0.1, 3, None):
                    with self.subTest(arch=arch, static=static, value=value):
                        h, refs = self.make(arch)
                        holder, call = self.get_call(h, refs, "double", static)
                        holder.retval = value
                        call()
                        expected = struct.unpack("<Q", struct.pack("<d", float(value or 0)))[0]
                        self.assertEqual(h.fp_return_bits(is_double=True), expected)

    def test_object(self):
        for static in (False, True):
            for arch in self.each_arch():
                with self.subTest(arch=arch, static=static):
                    h, refs = self.make(arch)
                    holder, call = self.get_call(h, refs, "object", static)
                    result = object()
                    holder.retval = result
                    ref = call()
                    self.assertIs(h.env.get_reference(ref).value, result)

                    holder.retval = None
                    self.assertEqual(call(), JAVA_NULL)

    def test_void_leaves_registers_alone(self):
        for static in (False, True):
            for arch in self.each_arch():
                with self.subTest(arch=arch, static=static):
                    h, refs = self.make(arch)
                    holder, call = self.get_call(h, refs, "void", static)
                    holder.retval = 123
                    self.assertEqual(call(), 0)   # r0/x0 still holds the first argument (env = 0)

    def test_requested_kind_decides_the_register_layout(self):
        # CallLongMethodA on a method that is declared to return int: the caller asked for a jlong
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                Target.retval = -1
                r0 = h.call("call_long_method_a", 0, h.obj_ref(Target()), self.mid(Target, 'get', '()I'), 0)
                if arch == emu_const.ARCH_ARM64:
                    self.assertEqual(r0, 0xFFFFFFFFFFFFFFFF)
                else:
                    self.assertEqual((r0, h.emu.registers.v_reg_1), (0xFFFFFFFF, 0xFFFFFFFF))

    def test_long_arguments_and_result_end_to_end(self):
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                h.write_jvalues([('jlong', (1 << 40)), ('jint', -1)])
                r0 = h.call("call_long_method_a", 0, h.obj_ref(Target()),
                            self.mid(Target, 'twoLongs', '(JI)J'), 0x10000)
                expected = (1 << 40) - 1
                if arch == emu_const.ARCH_ARM64:
                    self.assertEqual(r0, expected)
                else:
                    self.assertEqual((h.emu.registers.v_reg_1 << 32) | r0, expected)


class TestDispatchAndErrors(Base):

    def test_override_in_the_object_class_wins(self):
        # the id comes from Target.get, the object is a SubTarget: virtual dispatch
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                Target.retval = 5
                base_id = self.mid(Target, 'get', '()I')
                self.assertEqual(h.call("call_int_method_a", 0, h.obj_ref(SubTarget()), base_id, 0), 1005)
                self.assertEqual(h.call("call_int_method_a", 0, h.obj_ref(Target()), base_id, 0), 5)

    def test_alloc_object_then_constructor(self):
        # AllocObject + <init> through the jvalue[] call: the object is only usable after <init>
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                ref = h.call("alloc_object", 0, refs[Target])
                obj = h.env.get_reference(ref).value
                self.assertIsNone(obj.value)
                h.write_jvalues([('jint', 42)])
                h.call("call_void_method_a", 0, ref, self.mid(Target, '<init>', '(I)V'), 0x10000)
                self.assertEqual(obj.value, 42)

    def test_errors(self):
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                with self.assertRaises(ValueError):          # null receiver
                    h.call("call_int_method_a", 0, 0, 1, 0)
                with self.assertRaises(ValueError):          # not a jclass
                    h.call("call_static_int_method_a", 0, h.obj_ref(Target()), 1, 0)
                with self.assertRaisesRegex(RuntimeError, "Could not find method"):
                    h.call("call_int_method_a", 0, h.obj_ref(Target()), 0x7FFFFFF, 0)
                with self.assertRaisesRegex(RuntimeError, "Could not find static method"):
                    h.call("call_static_int_method_a", 0, refs[StaticTarget], 0x7FFFFFF, 0)

    def test_all_twenty_entries_are_implemented(self):
        # the nonvirtual variants are intentionally NOT part of this change
        for arch in self.each_arch():
            with self.subTest(arch=arch):
                h, refs = self.make(arch)
                for kind in RETURN_KINDS:
                    for name in (f"call_{kind}_method_a", f"call_static_{kind}_method_a"):
                        static = "static" in name
                        Target.retval = StaticTarget.retval = 0
                        if static:
                            fn_args = (0, refs[StaticTarget], self.mid(StaticTarget, 'get', '()I'), 0)
                        else:
                            fn_args = (0, h.obj_ref(Target()), self.mid(Target, 'get', '()I'), 0)
                        h.call(name, *fn_args)   # must not raise


class TestFpReturnOnRealUnicorn(unittest.TestCase):
    """
    The tests above use a fake Uc. This one checks the one thing a fake cannot prove: that
    real Unicorn accepts the register writes RegistersMapping.set_fp_return relies on.
    """

    def uc(self, arch_name):
        try:
            import unicorn
            if arch_name == "arm64":
                return unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
            return unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        except Exception as e:
            self.skipTest(f"real unicorn is not available: {e}")

    def test_arm64_float_and_double_land_in_s0_d0(self):
        from unicorn.arm64_const import UC_ARM64_REG_S0, UC_ARM64_REG_D0
        mu = self.uc("arm64")
        regs = RegistersMapping(mu, emu_const.ARCH_ARM64)
        regs.set_fp_return(0x3FC00000, is_double=False)
        self.assertEqual(mu.reg_read(UC_ARM64_REG_S0), 0x3FC00000)
        bits = struct.unpack("<Q", struct.pack("<d", -2.25))[0]
        regs.set_fp_return(bits, is_double=True)
        self.assertEqual(mu.reg_read(UC_ARM64_REG_D0), bits)

    def test_arm32_softfp(self):
        mu = self.uc("arm")
        regs = RegistersMapping(mu, emu_const.ARCH_ARM32)
        bits = struct.unpack("<Q", struct.pack("<d", -2.25))[0]
        regs.set_fp_return(bits, is_double=True)
        self.assertEqual((regs.v_reg_1 << 32) | regs.v_reg_0, bits)
        regs.set_fp_return(0x3FC00000, is_double=False)
        self.assertEqual(regs.v_reg_0, 0x3FC00000)


if __name__ == "__main__":
    unittest.main()
