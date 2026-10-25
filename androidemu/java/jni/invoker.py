import struct
import logging
from typing import TYPE_CHECKING, List, Optional

from ...const import emu_const
from ..jvm.constants import JAVA_NULL
from ...java.signature import ArgKind
from .constants import JNI_WIDE_OR_FP_KINDS
from .reference import jobject, jclass
from ...native.helpers.jni_native import (
    read_args32, read_args64,
    read_args_v32, read_args_v64,
    read_args_a32, read_args_a64,
    count_arg_words32, count_arg_words64
)
from ..classes.java.lang.throwable import JavaThrowable
from .utils import allocate_py_instance

if TYPE_CHECKING:
    from ...core.emulator import Emulator
    from ..class_def import JavaClassDef
    from ..classes.java.lang.clazz import Class
    from .main import JNIEnv

logger = logging.getLogger(__name__)


class JNIMethodInvoker:
    """
    Handles resolution, argument unpacking, execution and return-value marshaling
    for Java methods invoked through JNI (Call<Type>Method, CallNonvirtual<Type>Method,
    CallStatic<Type>Method and their *A / *V variants).
    """

    def __init__(self, env: "JNIEnv", arch: int):
        self._env = env
        self._arch = arch

        if arch == emu_const.ARCH_ARM32:
            self._read_args = read_args32
            self._read_args_v = read_args_v32
            self._read_args_a = read_args_a32
        elif arch == emu_const.ARCH_ARM64:
            self._read_args = read_args64
            self._read_args_v = read_args_v64
            self._read_args_a = read_args_a64
        else:
            raise NotImplementedError(f"Unsupported arch {arch}")

    def read_args_common(self, emu: "Emulator", args, args_kinds: tuple, arg_type: int, first_reg: int = 3) -> List:
        if arg_type == 0:
            if self._arch == emu_const.ARCH_ARM64:
                return self._read_args(self._env, emu.registers, args, args_kinds)
            return self._read_args(self._env, emu.registers, args, args_kinds, first_reg)
        elif arg_type == 1:
            return self._read_args_v(self._env, emu.memory, args, args_kinds)
        elif arg_type == 2:
            return self._read_args_a(self._env, emu.memory, args, args_kinds)
        raise RuntimeError(f"Unsupported arg_type: {arg_type}")

    def create_instance(self, emu: "Emulator", clazz_idx: int, method_id: int, args, args_type: int):
        jclazz = self._env.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = jclazz.value.get_py_clazz()
        
        obj = allocate_py_instance(pyclazz)

        method = pyclazz.find_method_by_id(method_id)
        if method.name != "<init>" or method.ret_kind != ArgKind.VOID:
            raise ValueError("Class constructor has the wrong name or does not return void.")

        first_reg = 4 if args_type == 0 else 3
        constructor_args = self.read_args_common(emu, args, method.args_kinds, args_type, first_reg=first_reg)
        try:
            method.func(obj, emu, *constructor_args)
        except JavaThrowable as exc: # if exception caused while calling <init> constructor
            self._env.throw_exception(jobject(exc))
            return JAVA_NULL if method.ret_kind in ("L", "") else 0
        
        return self._env.add_local_reference(jobject(obj))


    def resolve_instance_method(self, obj_idx: int, method_id: int, clazz_idx: Optional[int] = None):
        """
        Finds what an instance Call<T>Method / CallNonvirtual<T>Method has to run.
        Returns (pyobj, method, real_method): `method` (found by id) provides the argument types,
        `real_method` is the implementation to call.

          * virtual call (clazz_idx is None): the id is looked up in the object's class and the
            method is then looked up again by name, so an override in the object's own class wins
            over the one the id was taken from;
          * nonvirtual call (clazz_idx is the `clazz` argument): the id is looked up in that class
            (or its superclasses) and exactly that implementation is run on the object, whatever
            the class of the object is - this is how a constructor is called after AllocObject and
            how an overridden super method is called.
        """
        obj = self._env.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError(f"Expected a jobject, got {type(obj)} for ref {obj_idx:#x}")

        pyobj = self._env.jobject_to_pyobject(obj)
        obj_class: "JavaClassDef" = pyobj.__class__

        if clazz_idx is not None:
            jclazz = self._env.get_reference(clazz_idx)
            if not isinstance(jclazz, jclass):
                raise ValueError("Expected a jclass.")
            pyclazz = jclazz.value.get_py_clazz()

            method = pyclazz.find_method_by_id(method_id)
            if method is None:
                raise RuntimeError(f"Could not find method {method_id} in class {pyclazz.jvm_name} by id.")
            return pyobj, method, method

        method = obj_class.find_method_by_id(method_id)
        if method is not None:
            real_impl = obj_class.find_method(method.name, method.signature) or method
            return pyobj, method, real_impl

        glob_res = self._env._class_loader.resolve_method_globally(method_id)
        if glob_res is not None:
            declaring_class, method_decl = glob_res
            real_impl = obj_class.find_method(method_decl.name, method_decl.signature)
            if real_impl is not None:
                return pyobj, method_decl, real_impl

            return pyobj, method_decl, method_decl

        obj_cls_name = getattr(obj_class, 'jvm_name', type(pyobj).__name__)
        logger.error("[JNI] Failed to resolve method %d on instance of %s!", method_id, obj_cls_name)
        raise RuntimeError(f"Could not find method {method_id} in object {obj_cls_name} by id.")

    def arg_words(self, emu: "Emulator", args_kinds: tuple, first_reg: int) -> int:
        """Number of argument words to fetch for the variadic arguments of a Call<T>Method."""
        if not args_kinds:
            return 0
        if emu.arch == emu_const.ARCH_ARM64:
            return count_arg_words64(args_kinds) # jfloat/jdouble are in vector registers
        return count_arg_words32(args_kinds, first_reg)

    def dyncall(self, emu: "Emulator", is_static: bool, ret_kind: str = "", nonvirtual: bool = False):
        regs = emu.registers

        if nonvirtual:
            # CallNonvirtual<T>Method(env, obj, clazz, methodID, ...): the variadic arguments start
            # one register later than in Call<T>Method(env, obj, methodID, ...)
            first_reg = 4
            target_instance, method, real_method = self.resolve_instance_method(
                regs.v_reg_1, regs.v_reg_3, clazz_idx=regs.v_reg_2)
        else:
            first_reg = 3
            obj_or_cls_idx = regs.v_reg_1
            method_id = regs.v_reg_2

            target_ref = self._env.get_reference(obj_or_cls_idx)
            if not target_ref:
                raise RuntimeError(f"JNI CallMethod: invalid object/class ref {obj_or_cls_idx:#x}")

            pyobj_or_cls: 'Class' = self._env.jobject_to_pyobject(target_ref)
            if is_static:
                clazz = pyobj_or_cls.get_py_clazz()
                target_instance = None
            else:
                target_instance = pyobj_or_cls
                clazz = target_instance.__class__

            method = clazz.find_method_by_id(method_id)
            if method is None:
                name = getattr(clazz, 'jvm_name', str(clazz))
                raise RuntimeError(f"Could not find method {method_id} in {name} by id.")
            real_method = None if is_static else clazz.find_method(method.name, method.signature)

        n_words = self.arg_words(emu, method.args_kinds, first_reg=first_reg)
        raw_call_args = regs.read_args(first_reg + n_words)[first_reg:]
        call_args = self.read_args_common(emu, raw_call_args, method.args_kinds, arg_type=0, first_reg=first_reg)

        try:
            if is_static:
                v = method.func(emu, *call_args)
            else:
                v = real_method.func(target_instance, emu, *call_args)
        except JavaThrowable as exc:
            self._env.throw_exception(jobject(exc))
            return JAVA_NULL if ret_kind in ("L", "") else 0
        
        if ret_kind in JNI_WIDE_OR_FP_KINDS:
            return self.wide_or_fp_return(emu, v, ret_kind)
        if v is not None and not isinstance(v, (int, float, bool)):
            return self._env.add_local_reference(jobject(v))
        return v

    def dispatch_call(self, emu: "Emulator", is_static: bool, ret_kind: str = "", nonvirtual: bool = False):
        res = self.dyncall(emu, is_static, ret_kind, nonvirtual)
        if res is not None:
            if isinstance(res, tuple):
                emu.registers.v_reg_0, emu.registers.v_reg_1 = res
            else:
                emu.registers.v_reg_0 = res

    def call_varargs_method(self, emu: "Emulator", obj_idx: int, method_id: int, args_v, ret_kind: str = "",
                            clazz_idx: Optional[int] = None):
        pyobj, method, real_method = self.resolve_instance_method(obj_idx, method_id, clazz_idx)

        constructor_args = self.read_args_common(emu, args_v, method.args_kinds, arg_type=1)
        try:
            v = real_method.func(pyobj, emu, *constructor_args)
        except JavaThrowable as exc:
            self._env.throw_exception(jobject(exc))
            return JAVA_NULL if ret_kind in ("L", "") else 0
        if ret_kind in JNI_WIDE_OR_FP_KINDS:
            return self.wide_or_fp_return(emu, v, ret_kind)
        return v

    def call_static_varargs_method(self, emu: "Emulator", clazz_idx: int, method_id: int, args_v, ret_kind: str = ""):
        clazz = self._env.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(f"Could not find static method {method_id} by id.")

        constructor_args = self.read_args_common(emu, args_v, method.args_kinds, arg_type=1)
        try: v = method.func(emu, *constructor_args)
        except JavaThrowable as exc:
            self._env.throw_exception(jobject(exc))
            return JAVA_NULL if ret_kind in ("L", "") else 0
        
        if ret_kind in JNI_WIDE_OR_FP_KINDS:
            return self.wide_or_fp_return(emu, v, ret_kind)
        return v

    def call_a_method(self, emu: "Emulator", obj_idx: int, method_id: int, args_a: int, ret_kind: str,
                      clazz_idx: Optional[int] = None):
        """
        Call<Type>MethodA / CallStatic<Type>MethodA (arguments come as a jvalue[])

        ret_kind is the JNI return type letter of the function the native code actually called
        (Z B C S I J F D L V), NOT the declared one of the mocked method: it decides in which
        register(s) and in which width the result is handed back to the native caller.
        """
        pyobj, method, real_method = self.resolve_instance_method(obj_idx, method_id, clazz_idx)

        call_args = self.read_args_common(emu, args_a, method.args_kinds, arg_type=2)
        
        try: v = real_method.func(pyobj, emu, *call_args)
        except JavaThrowable as exc:
            self._env.throw_exception(jobject(exc))
            return JAVA_NULL if ret_kind in ("L", "") else 0
        
        return self.a_return(emu, v, ret_kind)

    def call_static_a_method(self, emu: "Emulator", clazz_idx: int, method_id: int, args_a: int, ret_kind: str):
        clazz = self._env.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        pyclazz = clazz.value.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(f"Could not find static method {method_id} by id.")

        call_args = self.read_args_common(emu, args_a, method.args_kinds, arg_type=2)
        v = method.func(emu, *call_args)
        return self.a_return(emu, v, ret_kind)

    def a_return(self, emu: "Emulator", v, ret_kind: str):
        """
        Converts what a mocked method returned into what native_method has to put into the
        return register(s). float/double are written here (they do not travel in r0/x0) and
        None is returned so that native_method does not overwrite them.
        """
        if ret_kind == "V":
            return None

        if ret_kind == "L":
            if v is None:
                return JAVA_NULL
            if isinstance(v, int):  # JAVA_NULL or an already created reference
                return v
            return self._env.add_local_reference(v if isinstance(v, jobject) else jobject(v))

        if ret_kind in JNI_WIDE_OR_FP_KINDS:
            return self.wide_or_fp_return(emu, v, ret_kind)

        iv = 0 if v is None else int(v)
        if ret_kind == "Z":
            return 1 if iv else 0
        if ret_kind == "B":
            return iv & 0xFF
        if ret_kind == "C" or ret_kind == "S":
            return iv & 0xFFFF
        if ret_kind == "I":
            return iv & 0xFFFFFFFF
        raise ValueError(f"Unknown return kind {ret_kind!r}")

    def wide_or_fp_return(self, emu: "Emulator", v, ret_kind: str):
        """
        jlong ("J"), jfloat ("F") and jdouble ("D") results, for every kind of call and field getter.

          ARM64: a jlong is one 64 bit value in x0; float/double are returned in s0/d0.
          ARM32: a jlong / jdouble is a r0 (low) : r1 (high) pair, a jfloat is in r0 (softfp).

        Returns what native_method has to put into the return registers: an int for x0, a
        (low, high) tuple for r0:r1, or None when the value has already been written here
        (float/double do not travel in r0/x0).
        """
        if ret_kind == "J":
            iv = (0 if v is None else int(v)) & 0xFFFFFFFFFFFFFFFF
            if emu.arch == emu_const.ARCH_ARM64:
                return iv
            return (iv & 0xFFFFFFFF, iv >> 32)

        v = 0.0 if v is None else float(v)
        if ret_kind == "D":
            bits = struct.unpack("<Q", struct.pack("<d", v))[0]
        else:
            try:
                bits = struct.unpack("<I", struct.pack("<f", v))[0]
            except OverflowError:  # out of the float range -> +-inf, as a Java (float) cast does
                bits = 0x7F800000 if v > 0 else 0xFF800000
        emu.registers.set_fp_return(bits, is_double=(ret_kind == "D"))
        return None