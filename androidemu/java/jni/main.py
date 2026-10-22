import inspect
import logging
import struct
from array import array as _pyarray
from typing import TYPE_CHECKING, List, Optional

from unicorn import *

from ...const import emu_const
from ..jvm.constants import JAVA_NULL, MODIFIER_STATIC
from .constants import *
from .reference import jobject, jclass
from ..reference_table import ReferenceTable
from ...native.helpers.jni_native import (
    read_args32, read_args64,
    read_args_v32, read_args_v64,
    read_args_a32, read_args_a64,
    count_arg_words32, count_arg_words64
)
from ...native.helpers.method import native_method
from ..class_def import JavaClassDef
from ...utils.memory import helpers
from ...highlevel.libc import LibC
from ...types import ptr_t

if TYPE_CHECKING:
    from ...core.emulator import Emulator
    from ..classloader import JavaClassLoader
    from ..classes.java.lang.clazz import Class
    from ...utils.hooker import Hooker

logger = logging.getLogger(__name__)


# Primitive arrays (everything but byte[], which keeps its bytearray code):
# JNI type letter -> (struct format to read a native element, format to write it, bytes per element)
_PRIM_ELEMENT = {
    "Z": ("B", "B", 1), "C": ("H", "H", 2), "S": ("h", "H", 2), "I": ("i", "I", 4),
    "J": ("q", "Q", 8), "F": ("f", "f", 4), "D": ("d", "d", 8),
}
_PRIM_NAME = {"Z": "Boolean", "C": "Char", "S": "Short", "I": "Int", "J": "Long", "F": "Float", "D": "Double"}


def _pack_elements(kind: str, values) -> bytes:
    """Python items -> the bytes of a native array. Integers are masked to their width, so signed and unsigned items both work."""
    _, wfmt, size = _PRIM_ELEMENT[kind]
    if kind == "Z":
        values = [1 if v else 0 for v in values]
    elif kind in "CSIJ":
        mask = (1 << (8 * size)) - 1
        values = [int(v) & mask for v in values]
    else:
        values = [float(v) for v in values]
    try:
        return struct.pack(f"<{len(values)}{wfmt}", *values)
    except OverflowError:  # a float outside of the float32 range: +-inf, as a Java (float) cast gives
        inf = float("inf")
        return struct.pack(f"<{len(values)}f", *[v if abs(v) <= 3.4028234663852886e38 else (inf if v > 0 else -inf) for v in values])


def _unpack_elements(kind: str, data: bytes) -> list:
    """The bytes of a native array -> Python items with Java semantics (signed short/int/long, unsigned char, boolean 0/1)."""
    rfmt, _, size = _PRIM_ELEMENT[kind]
    values = list(struct.unpack(f"<{len(data) // size}{rfmt}", data))
    if kind == "Z":
        values = [1 if v else 0 for v in values]
    return values


def _assign_region(pyobj, start: int, values: list) -> None:
    """array[start:start+len(values)] = values, IN PLACE, whatever the array keeps its items in."""
    items = pyobj.get_py_items()
    end = start + len(values)
    if isinstance(items, _pyarray):
        items[start:end] = _pyarray(items.typecode, values)
        return
    if isinstance(items, (bytes, tuple)):  # immutable backing store: swap it, keep the Java object
        items = list(items)
        pyobj.pyobject = items
    items[start:end] = values


def _jint(v: int) -> int:
    """A jint / jsize argument as a signed 32 bit number (the upper register bits are not meaningful)."""
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def _allocate_py_instance(pyclazz: JavaClassDef):
    """
    Creates the Python object behind a Java instance WITHOUT running any Java constructor.

    ``NewObject*`` does ``pyclazz()`` and then calls the mocked ``<init>``. ``AllocObject``
    must do only the first half (JNI spec: the object is allocated "without invoking any of
    the object's constructors"), so the mocked ``<init>`` is never touched here - native code
    runs it later itself (``CallNonvirtual<Void>Method*`` / ``Call<Void>Method*``).

    The Python-level ``__init__`` is the mock's default-state initializer, not a Java
    constructor, so it is still run when it can be called without arguments (the same state
    a ``NewObject`` instance has before ``<init>`` runs). Mocks whose ``__init__`` requires
    arguments are allocated "raw" through ``__new__`` instead of failing.

    The signature is inspected instead of catching ``TypeError`` so that a real ``TypeError``
    raised inside a mock's ``__init__`` is not silently swallowed.
    """
    init = pyclazz.__init__
    callable_without_args = init is object.__init__
    if not callable_without_args:
        try:
            inspect.signature(init).bind(None)  # None stands for `self`
            callable_without_args = True
        except (TypeError, ValueError):  # required args are missing / no signature available
            callable_without_args = False

    if callable_without_args:
        return pyclazz()
    return pyclazz.__new__(pyclazz)


# JNI return kinds that are not returned like an int: jlong, jfloat, jdouble (see JNIEnv.__wide_or_fp_return)
_WIDE_OR_FP_KINDS = ("J", "F", "D")


class JNIEnv:
    """
    Simulated JNIEnv (JNINativeInterface).
    """

    # =========================================================================
    # 1. INTERNAL HELPERS & CALL DISPATCHER
    # =========================================================================

    def __read_args_common(self, emu: "Emulator", args, args_type_list, arg_type: int, first_reg: int = 3) -> List:
        if arg_type == 0:
            return self.__read_args(self, emu.mu, args, args_type_list, first_reg)
        elif arg_type == 1:
            return self.__read_args_v(self, emu.mu, args, args_type_list)
        elif arg_type == 2:
            return self.__read_args_a(self, emu.mu, args, args_type_list)
        raise RuntimeError(f"Unsupported arg_type: {arg_type}")

    @staticmethod
    def jobject_to_pyobject(obj: jobject) -> object:
        if isinstance(obj, jobject):
            return obj.value
        raise RuntimeError(f"jobject_to_pyobject: unknown object type {type(obj)!r}")

    def get_reference(self, idx: int) -> Optional[jobject]:
        if idx == 0:
            return None
        if self._locals.in_range(idx):
            return self._locals.get(idx)
        if self._globals.in_range(idx):
            return self._globals.get(idx)
        raise RuntimeError(f"Invalid get_reference({idx:#x})")

    def add_local_reference(self, obj: jobject) -> int:
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        return self._locals.add(obj)

    def set_local_reference(self, idx: int, newobj: jobject) -> None:
        if not isinstance(newobj, jobject):
            raise ValueError("Expected a jobject.")
        self._locals.set(idx, newobj)

    def get_local_reference(self, idx: int) -> Optional[jobject]:
        return self._locals.get(idx)

    def delete_local_reference(self, obj: jobject) -> None:
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        self._locals.remove(obj)

    def clear_locals(self) -> None:
        self._locals.clear()

    def add_global_reference(self, obj: jobject) -> int:
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        return self._globals.add(obj)

    def get_global_reference(self, idx: int) -> Optional[jobject]:
        return self._globals.get(idx)

    def delete_global_reference(self, obj: jobject) -> None:
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        self._globals.remove(obj)

    def __dyncall(self, emu: "Emulator", is_static: bool, ret_kind: str = "", nonvirtual: bool = False):
        regs = emu.registers

        if nonvirtual:
            # CallNonvirtual<T>Method(env, obj, clazz, methodID, ...): the variadic arguments start
            # one register later than in Call<T>Method(env, obj, methodID, ...)
            first_reg = 4
            target_instance, method, real_method = self.__resolve_instance_method(
                regs.v_reg_1, regs.v_reg_3, clazz_idx=regs.v_reg_2)
        else:
            first_reg = 3
            obj_or_cls_idx = regs.v_reg_1
            method_id = regs.v_reg_2

            target_ref = self.get_reference(obj_or_cls_idx)
            if not target_ref:
                raise RuntimeError(f"JNI CallMethod: invalid object/class ref {obj_or_cls_idx:#x}")

            pyobj_or_cls: 'Class' = self.jobject_to_pyobject(target_ref)
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

        n_words = self.__arg_words(emu, method.args_list, first_reg=first_reg)
        raw_call_args = regs.read_args(first_reg + n_words)[first_reg:]
        call_args = self.__read_args_common(emu, raw_call_args, method.args_list, arg_type=0, first_reg=first_reg)

        if is_static:
            v = method.func(emu, *call_args)
        else:
            v = real_method.func(target_instance, emu, *call_args)

        if ret_kind in _WIDE_OR_FP_KINDS:
            return self.__wide_or_fp_return(emu, v, ret_kind)
        if v is not None and not isinstance(v, (int, float, bool)):
            return self.add_local_reference(jobject(v))
        return v

    def __resolve_instance_method(self, obj_idx: int, method_id: int, clazz_idx: Optional[int] = None):
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
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = self.jobject_to_pyobject(obj)

        if clazz_idx is None:
            clazz: "JavaClassDef" = pyobj.__class__
            method = clazz.find_method_by_id(method_id)
            if method is None:
                raise RuntimeError(f"Could not find method {method_id} in object by id.")
            return pyobj, method, clazz.find_method(method.name, method.signature) or method

        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = jclazz.value.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(f"Could not find method {method_id} in class {pyclazz.jvm_name} by id.")
        return pyobj, method, method

    @staticmethod
    def __arg_words(emu: "Emulator", args_list, first_reg: int) -> int:
        """Number of argument words to fetch for the variadic arguments of a Call<T>Method."""
        if not args_list:
            return 0
        if emu.arch == emu_const.ARCH_ARM64:
            return count_arg_words64(args_list)  # jfloat/jdouble are in vector registers
        return count_arg_words32(args_list, first_reg)

    # ret_kind is "J" (long), "F" (float), "D" (double) or "" for everything else: those three
    # are not returned like an int, see __wide_or_fp_return
    def __dispatch_call(self, emu: "Emulator", is_static: bool, ret_kind: str = "", nonvirtual: bool = False):
        res = self.__dyncall(emu, is_static, ret_kind, nonvirtual)
        if res is not None:
            if isinstance(res, tuple):
                emu.registers.v_reg_0, emu.registers.v_reg_1 = res
            else:
                emu.registers.v_reg_0 = res

    def __call_varargs_method(self, emu: "Emulator", env, obj_idx: int, method_id: int, args_v, ret_kind: str = "",
                              clazz_idx: Optional[int] = None):
        pyobj, method, real_method = self.__resolve_instance_method(obj_idx, method_id, clazz_idx)

        constructor_args = self.__read_args_common(emu, args_v, method.args_list, arg_type=1)
        v = real_method.func(pyobj, emu, *constructor_args)

        if ret_kind in _WIDE_OR_FP_KINDS:
            return self.__wide_or_fp_return(emu, v, ret_kind)
        return v

    def __call_static_varargs_method(self, emu: "Emulator", env, clazz_idx: int, method_id: int, args_v, ret_kind: str = ""):
        clazz = self.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(f"Could not find static method {method_id} by id.")

        constructor_args = self.__read_args_common(emu, args_v, method.args_list, arg_type=1)
        v = method.func(emu, *constructor_args)

        if ret_kind in _WIDE_OR_FP_KINDS:
            return self.__wide_or_fp_return(emu, v, ret_kind)
        return v

    # Call<Type>MethodA / CallStatic<Type>MethodA (arguments come as a jvalue[])
    #
    # ret_kind is the JNI return type letter of the function the native code actually called
    # (Z B C S I J F D L V), NOT the declared one of the mocked method: it decides in which
    # register(s) and in which width the result is handed back to the native caller.
    def __call_a_method(self, emu: "Emulator", obj_idx: int, method_id: int, args_a: int, ret_kind: str,
                        clazz_idx: Optional[int] = None):
        pyobj, method, real_method = self.__resolve_instance_method(obj_idx, method_id, clazz_idx)

        call_args = self.__read_args_common(emu, args_a, method.args_list, arg_type=2)
        v = real_method.func(pyobj, emu, *call_args)
        return self.__a_return(emu, v, ret_kind)

    def __call_static_a_method(self, emu: "Emulator", clazz_idx: int, method_id: int, args_a: int, ret_kind: str):
        clazz = self.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        pyclazz = clazz.value.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(f"Could not find static method {method_id} by id.")

        call_args = self.__read_args_common(emu, args_a, method.args_list, arg_type=2)
        v = method.func(emu, *call_args)
        return self.__a_return(emu, v, ret_kind)

    def __a_return(self, emu: "Emulator", v, ret_kind: str):
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
            if isinstance(v, int): # JAVA_NULL or an already created reference
                return v
            return self.add_local_reference(v if isinstance(v, jobject) else jobject(v))

        if ret_kind in _WIDE_OR_FP_KINDS:
            return self.__wide_or_fp_return(emu, v, ret_kind)

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

    def __wide_or_fp_return(self, emu: "Emulator", v, ret_kind: str):
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
            except OverflowError: # out of the float range -> +-inf, as a Java (float) cast does
                bits = 0x7F800000 if v > 0 else 0xFF800000
        emu.registers.set_fp_return(bits, is_double=(ret_kind == "D"))
        return None

    # =========================================================================
    # 2. INITIALIZATION & VTABLE MAPPING
    # =========================================================================

    def __init__(self, emu: "Emulator", class_loader: "JavaClassLoader", hooker: "Hooker"):
        self._class_loader: "JavaClassLoader" = class_loader
        self._string = self._class_loader.find_class_by_name('java/lang/String')
        self._array = self._class_loader.find_class_by_name('java/lang/reflect/Array')

        self._locals = ReferenceTable(start=1, max_entries=2048)
        self._globals = ReferenceTable(start=4096, max_entries=512000)
        self.__libc = LibC(emu)

        arch = emu.arch
        if arch == emu_const.ARCH_ARM32:
            self.__read_args = read_args32
            self.__read_args_v = read_args_v32
            self.__read_args_a = read_args_a32
        elif arch == emu_const.ARCH_ARM64:
            self.__read_args = read_args64
            self.__read_args_v = read_args_v64
            self.__read_args_a = read_args_a64
        else:
            raise NotImplementedError(f"Unsupported arch {arch}")

        self.address_ptr, self.address = hooker.write_function_table({
                4: self.get_version,
                5: self.define_class,
                6: self.find_class,
                7: self.from_reflected_method,
                8: self.from_reflected_field,
                9: self.to_reflected_method,
                10: self.get_superclass,
                11: self.is_assignable_from,
                12: self.to_reflected_field,
                13: self.throw,
                14: self.throw_new,
                15: self.exception_occurred,
                16: self.exception_describe,
                17: self.exception_clear,
                18: self.fatal_error,
                19: self.push_local_frame,
                20: self.pop_local_frame,
                21: self.new_global_ref,
                22: self.delete_global_ref,
                23: self.delete_local_ref,
                24: self.is_same_object,
                25: self.new_local_ref,
                26: self.ensure_local_capacity,
                27: self.alloc_object,
                28: self.new_object,
                29: self.new_object_v,
                30: self.new_object_a,
                31: self.get_object_class,
                32: self.is_instance_of,
                33: self.get_method_id,
                34: self.call_object_method,
                35: self.call_object_method_v,
                36: self.call_object_method_a,
                37: self.call_boolean_method,
                38: self.call_boolean_method_v,
                39: self.call_boolean_method_a,
                40: self.call_byte_method,
                41: self.call_byte_method_v,
                42: self.call_byte_method_a,
                43: self.call_char_method,
                44: self.call_char_method_v,
                45: self.call_char_method_a,
                46: self.call_short_method,
                47: self.call_short_method_v,
                48: self.call_short_method_a,
                49: self.call_int_method,
                50: self.call_int_method_v,
                51: self.call_int_method_a,
                52: self.call_long_method,
                53: self.call_long_method_v,
                54: self.call_long_method_a,
                55: self.call_float_method,
                56: self.call_float_method_v,
                57: self.call_float_method_a,
                58: self.call_double_method,
                59: self.call_double_method_v,
                60: self.call_double_method_a,
                61: self.call_void_method,
                62: self.call_void_method_v,
                63: self.call_void_method_a,
                64: self.call_nonvirtual_object_method,
                65: self.call_nonvirtual_object_method_v,
                66: self.call_nonvirtual_object_method_a,
                67: self.call_nonvirtual_boolean_method,
                68: self.call_nonvirtual_boolean_method_v,
                69: self.call_nonvirtual_boolean_method_a,
                70: self.call_nonvirtual_byte_method,
                71: self.call_nonvirtual_byte_method_v,
                72: self.call_nonvirtual_byte_method_a,
                73: self.call_nonvirtual_char_method,
                74: self.call_nonvirtual_char_method_v,
                75: self.call_nonvirtual_char_method_a,
                76: self.call_nonvirtual_short_method,
                77: self.call_nonvirtual_short_method_v,
                78: self.call_nonvirtual_short_method_a,
                79: self.call_nonvirtual_int_method,
                80: self.call_nonvirtual_int_method_v,
                81: self.call_nonvirtual_int_method_a,
                82: self.call_nonvirtual_long_method,
                83: self.call_nonvirtual_long_method_v,
                84: self.call_nonvirtual_long_method_a,
                85: self.call_nonvirtual_float_method,
                86: self.call_nonvirtual_float_method_v,
                87: self.call_nonvirtual_float_method_a,
                88: self.call_nonvirtual_double_method,
                89: self.call_nonvirtual_double_method_v,
                90: self.call_nonvirtual_double_method_a,
                91: self.call_nonvirtual_void_method,
                92: self.call_nonvirtual_void_method_v,
                93: self.call_nonvirtual_void_method_a,
                94: self.get_field_id,
                95: self.get_object_field,
                96: self.get_boolean_field,
                97: self.get_byte_field,
                98: self.get_char_field,
                99: self.get_short_field,
                100: self.get_int_field,
                101: self.get_long_field,
                102: self.get_float_field,
                103: self.get_double_field,
                104: self.set_object_field,
                105: self.set_boolean_field,
                106: self.set_byte_field,
                107: self.set_char_field,
                108: self.set_short_field,
                109: self.set_int_field,
                110: self.set_long_field,
                111: self.set_float_field,
                112: self.set_double_field,
                113: self.get_static_method_id,
                114: self.call_static_object_method,
                115: self.call_static_object_method_v,
                116: self.call_static_object_method_a,
                117: self.call_static_boolean_method,
                118: self.call_static_boolean_method_v,
                119: self.call_static_boolean_method_a,
                120: self.call_static_byte_method,
                121: self.call_static_byte_method_v,
                122: self.call_static_byte_method_a,
                123: self.call_static_char_method,
                124: self.call_static_char_method_v,
                125: self.call_static_char_method_a,
                126: self.call_static_short_method,
                127: self.call_static_short_method_v,
                128: self.call_static_short_method_a,
                129: self.call_static_int_method,
                130: self.call_static_int_method_v,
                131: self.call_static_int_method_a,
                132: self.call_static_long_method,
                133: self.call_static_long_method_v,
                134: self.call_static_long_method_a,
                135: self.call_static_float_method,
                136: self.call_static_float_method_v,
                137: self.call_static_float_method_a,
                138: self.call_static_double_method,
                139: self.call_static_double_method_v,
                140: self.call_static_double_method_a,
                141: self.call_static_void_method,
                142: self.call_static_void_method_v,
                143: self.call_static_void_method_a,
                144: self.get_static_field_id,
                145: self.get_static_object_field,
                146: self.get_static_boolean_field,
                147: self.get_static_byte_field,
                148: self.get_static_char_field,
                149: self.get_static_short_field,
                150: self.get_static_int_field,
                151: self.get_static_long_field,
                152: self.get_static_float_field,
                153: self.get_static_double_field,
                154: self.set_static_object_field,
                155: self.set_static_boolean_field,
                156: self.set_static_byte_field,
                157: self.set_static_char_field,
                158: self.set_static_short_field,
                159: self.set_static_int_field,
                160: self.set_static_long_field,
                161: self.set_static_float_field,
                162: self.set_static_double_field,
                163: self.new_string,
                164: self.get_string_length,
                165: self.get_string_chars,
                166: self.release_string_chars,
                167: self.new_string_utf,
                168: self.get_string_utf_length,
                169: self.get_string_utf_chars,
                170: self.release_string_utf_chars,
                171: self.get_array_length,
                172: self.new_object_array,
                173: self.get_object_array_element,
                174: self.set_object_array_element,
                175: self.new_boolean_array,
                176: self.new_byte_array,
                177: self.new_char_array,
                178: self.new_short_array,
                179: self.new_int_array,
                180: self.new_long_array,
                181: self.new_float_array,
                182: self.new_double_array,
                183: self.get_boolean_array_elements,
                184: self.get_byte_array_elements,
                185: self.get_char_array_elements,
                186: self.get_short_array_elements,
                187: self.get_int_array_elements,
                188: self.get_long_array_elements,
                189: self.get_float_array_elements,
                190: self.get_double_array_elements,
                191: self.release_boolean_array_elements,
                192: self.release_byte_array_elements,
                193: self.release_char_array_elements,
                194: self.release_short_array_elements,
                195: self.release_int_array_elements,
                196: self.release_long_array_elements,
                197: self.release_float_array_elements,
                198: self.release_double_array_elements,
                199: self.get_boolean_array_region,
                200: self.get_byte_array_region,
                201: self.get_char_array_region,
                202: self.get_short_array_region,
                203: self.get_int_array_region,
                204: self.get_long_array_region,
                205: self.get_float_array_region,
                206: self.get_double_array_region,
                207: self.set_boolean_array_region,
                208: self.set_byte_array_region,
                209: self.set_char_array_region,
                210: self.set_short_array_region,
                211: self.set_int_array_region,
                212: self.set_long_array_region,
                213: self.set_float_array_region,
                214: self.set_double_array_region,
                215: self.register_natives,
                216: self.unregister_natives,
                217: self.monitor_enter,
                218: self.monitor_exit,
                219: self.get_java_vm,
                220: self.get_string_region,
                221: self.get_string_utf_region,
                222: self.get_primitive_array_critical,
                223: self.release_primitive_array_critical,
                224: self.get_string_critical,
                225: self.release_string_critical,
                226: self.new_weak_global_ref,
                227: self.delete_weak_global_ref,
                228: self.exception_check,
                229: self.new_direct_byte_buffer,
                230: self.get_direct_buffer_address,
                231: self.get_direct_buffer_capacity,
                232: self.get_object_ref_type,
            })

    # =========================================================================
    # 3. METHOD INVOCATION (DYNAMIC / AUTO-ARITY)
    # =========================================================================

    def call_object_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=False)
    def call_boolean_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False)
    def call_byte_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False)
    def call_char_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False)
    def call_short_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=False)
    def call_int_method(self, emu: "Emulator"):     self.__dispatch_call(emu, is_static=False)
    def call_long_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False, ret_kind="J")
    def call_float_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=False, ret_kind="F")
    def call_double_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=False, ret_kind="D")
    def call_void_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False)

    def call_static_object_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=True)
    def call_static_boolean_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=True)
    def call_static_byte_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True)
    def call_static_char_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True)
    def call_static_short_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=True)
    def call_static_int_method(self, emu: "Emulator"):     self.__dispatch_call(emu, is_static=True)
    def call_static_long_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True, ret_kind="J")
    def call_static_float_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=True, ret_kind="F")
    def call_static_double_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=True, ret_kind="D")
    def call_static_void_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True)

    # =========================================================================
    # 4. METHOD INVOCATION (VARARGS: _v / _a)
    # =========================================================================

    @native_method
    def call_object_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_boolean_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_byte_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_char_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_short_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_int_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_long_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, "J")

    @native_method
    def call_float_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, "F")

    @native_method
    def call_double_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, "D")

    @native_method
    def call_void_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_static_object_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    @native_method
    def call_static_boolean_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    @native_method
    def call_static_byte_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    @native_method
    def call_static_char_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    @native_method
    def call_static_short_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    @native_method
    def call_static_int_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    @native_method
    def call_static_long_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, "J")

    @native_method
    def call_static_float_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, "F")

    @native_method
    def call_static_double_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, "D")

    @native_method
    def call_static_void_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    # jvalue[] variants
    @native_method
    def call_object_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "L")

    @native_method
    def call_boolean_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "Z")

    @native_method
    def call_byte_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "B")

    @native_method
    def call_char_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "C")

    @native_method
    def call_short_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "S")

    @native_method
    def call_int_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "I")

    @native_method
    def call_long_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "J")

    @native_method
    def call_float_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "F")

    @native_method
    def call_double_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "D")

    @native_method
    def call_void_method_a(self, emu: "Emulator", env, obj_idx, method_id, args):
        self.__call_a_method(emu, obj_idx, method_id, args, "V")

    @native_method
    def call_static_object_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "L")

    @native_method
    def call_static_boolean_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "Z")

    @native_method
    def call_static_byte_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "B")

    @native_method
    def call_static_char_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "C")

    @native_method
    def call_static_short_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "S")

    @native_method
    def call_static_int_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "I")

    @native_method
    def call_static_long_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "J")

    @native_method
    def call_static_float_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "F")

    @native_method
    def call_static_double_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_a_method(emu, clazz_idx, method_id, args, "D")

    @native_method
    def call_static_void_method_a(self, emu: "Emulator", env, clazz_idx, method_id, args):
        self.__call_static_a_method(emu, clazz_idx, method_id, args, "V")

    # CallNonvirtual<T>Method*(env, obj, clazz, methodID, ...): run the implementation that `clazz`
    # provides for `methodID` on `obj` (no virtual dispatch), see __resolve_instance_method
    def call_nonvirtual_object_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, nonvirtual=True)
    def call_nonvirtual_boolean_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, nonvirtual=True)
    def call_nonvirtual_byte_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, nonvirtual=True)
    def call_nonvirtual_char_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, nonvirtual=True)
    def call_nonvirtual_short_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, nonvirtual=True)
    def call_nonvirtual_int_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, nonvirtual=True)
    def call_nonvirtual_long_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, ret_kind="J", nonvirtual=True)
    def call_nonvirtual_float_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, ret_kind="F", nonvirtual=True)
    def call_nonvirtual_double_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, ret_kind="D", nonvirtual=True)
    def call_nonvirtual_void_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, nonvirtual=True)

    @native_method
    def call_nonvirtual_object_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_boolean_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_byte_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_char_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_short_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_int_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_long_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, "J", clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_float_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, "F", clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_double_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, "D", clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_void_method_v(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        self.__call_varargs_method(emu, env, obj_idx, method_id, args, clazz_idx=clazz_idx)

    @native_method
    def call_nonvirtual_object_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "L", clazz_idx)

    @native_method
    def call_nonvirtual_boolean_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "Z", clazz_idx)

    @native_method
    def call_nonvirtual_byte_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "B", clazz_idx)

    @native_method
    def call_nonvirtual_char_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "C", clazz_idx)

    @native_method
    def call_nonvirtual_short_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "S", clazz_idx)

    @native_method
    def call_nonvirtual_int_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "I", clazz_idx)

    @native_method
    def call_nonvirtual_long_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "J", clazz_idx)

    @native_method
    def call_nonvirtual_float_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "F", clazz_idx)

    @native_method
    def call_nonvirtual_double_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        return self.__call_a_method(emu, obj_idx, method_id, args, "D", clazz_idx)

    @native_method
    def call_nonvirtual_void_method_a(self, emu: "Emulator", env, obj_idx, clazz_idx, method_id, args):
        self.__call_a_method(emu, obj_idx, method_id, args, "V", clazz_idx)

    # =========================================================================
    # 5. FIELD ACCESS (INSTANCE & STATIC)
    # =========================================================================

    @native_method
    def get_field_id(self, emu: "Emulator", env, clazz_idx, name_ptr, sig_ptr):
        name = helpers.read_utf8(emu.mu, name_ptr)
        sig = helpers.read_utf8(emu.mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, False)
        if field is None:
            raise RuntimeError(f"Could not find field ('{name}', '{sig}') in class {pyclazz.jvm_name}.")
        return 0 if field.ignore else field.jvm_id

    def __get_field_val(self, emu: "Emulator", obj_idx: int, field_id: int, ret_kind: str = ""):
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = self.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)
        if field is None:
            raise RuntimeError(f"Could not find field {field_id} in object {pyobj.jvm_name} by id.")

        v = getattr(pyobj, field.name)
        if ret_kind in _WIDE_OR_FP_KINDS:
            return self.__wide_or_fp_return(emu, v, ret_kind)
        return v

    @native_method
    def get_object_field(self, emu: "Emulator", env, obj_idx, field_id):  return self.__get_field_val(emu, obj_idx, field_id)
    @native_method
    def get_boolean_field(self, emu: "Emulator", env, obj_idx, field_id): return self.__get_field_val(emu, obj_idx, field_id)
    @native_method
    def get_byte_field(self, emu: "Emulator", env, obj_idx, field_id):    return self.__get_field_val(emu, obj_idx, field_id)
    @native_method
    def get_char_field(self, emu: "Emulator", env, obj_idx, field_id):    return self.__get_field_val(emu, obj_idx, field_id)
    @native_method
    def get_short_field(self, emu: "Emulator", env, obj_idx, field_id):   return self.__get_field_val(emu, obj_idx, field_id)
    @native_method
    def get_int_field(self, emu: "Emulator", env, obj_idx, field_id):     return self.__get_field_val(emu, obj_idx, field_id)
    @native_method
    def get_long_field(self, emu: "Emulator", env, obj_idx, field_id):    return self.__get_field_val(emu, obj_idx, field_id, "J")
    @native_method
    def get_float_field(self, emu: "Emulator", env, obj_idx, field_id):   return self.__get_field_val(emu, obj_idx, field_id, "F")
    @native_method
    def get_double_field(self, emu: "Emulator", env, obj_idx, field_id):  return self.__get_field_val(emu, obj_idx, field_id, "D")

    def __set_field_val(self, emu: "Emulator", obj_idx: int, field_id: int, value, is_obj: bool = False):
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = self.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)
        if field is None:
            raise RuntimeError(f"Could not find field {field_id} in object {pyobj.jvm_name} by id.")

        v = self.jobject_to_pyobject(self.get_reference(value)) if is_obj else value
        setattr(pyobj, field.name, v)

    @native_method
    def set_object_field(self, emu: "Emulator", env, obj_idx, field_id, value):  self.__set_field_val(emu, obj_idx, field_id, value, is_obj=True)
    @native_method
    def set_boolean_field(self, emu: "Emulator", env, obj_idx, field_id, value): self.__set_field_val(emu, obj_idx, field_id, value)
    @native_method
    def set_byte_field(self, emu: "Emulator", env, obj_idx, field_id, value):    self.__set_field_val(emu, obj_idx, field_id, value)
    @native_method
    def set_char_field(self, emu: "Emulator", env, obj_idx, field_id, value):    self.__set_field_val(emu, obj_idx, field_id, value)
    @native_method
    def set_short_field(self, emu: "Emulator", env, obj_idx, field_id, value):   self.__set_field_val(emu, obj_idx, field_id, value)
    @native_method
    def set_int_field(self, emu: "Emulator", env, obj_idx, field_id, value):     self.__set_field_val(emu, obj_idx, field_id, value)
    @native_method
    def set_long_field(self, emu: "Emulator", env, obj_idx, field_id, value):    self.__set_field_val(emu, obj_idx, field_id, value)
    @native_method
    def set_float_field(self, emu: "Emulator", env, obj_idx, field_id, value):   self.__set_field_val(emu, obj_idx, field_id, value)
    @native_method
    def set_double_field(self, emu: "Emulator", env, obj_idx, field_id, value):  self.__set_field_val(emu, obj_idx, field_id, value)

    # Static Fields
    @native_method
    def get_static_field_id(self, emu: "Emulator", env, clazz_idx, name_ptr, sig_ptr):
        name = helpers.read_utf8(emu.mu, name_ptr)
        sig = helpers.read_utf8(emu.mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, True)
        if field is None:
            raise RuntimeError(f"Could not find static field ('{name}', '{sig}') in class {pyclazz.jvm_name}.")
        return 0 if field.ignore else field.jvm_id

    def __get_static_field_val(self, emu: "Emulator", clazz_idx: int, field_id: int, ret_kind: str = ""):
        clazz = self.get_reference(clazz_idx)
        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)
        v = field.static_value
        if ret_kind in _WIDE_OR_FP_KINDS:
            return self.__wide_or_fp_return(emu, v, ret_kind)
        return v

    @native_method
    def get_static_object_field(self, emu: "Emulator", env, clazz_idx, field_id):  return self.__get_static_field_val(emu, clazz_idx, field_id)
    @native_method
    def get_static_boolean_field(self, emu: "Emulator", env, clazz_idx, field_id): return self.__get_static_field_val(emu, clazz_idx, field_id)
    @native_method
    def get_static_byte_field(self, emu, env, clazz_idx, field_id):                return self.__get_static_field_val(emu, clazz_idx, field_id)
    @native_method
    def get_static_char_field(self, emu: "Emulator", env, clazz_idx, field_id):    return self.__get_static_field_val(emu, clazz_idx, field_id)
    @native_method
    def get_static_short_field(self, emu: "Emulator", env, clazz_idx, field_id):   return self.__get_static_field_val(emu, clazz_idx, field_id)
    @native_method
    def get_static_int_field(self, emu: "Emulator", env, clazz_idx, field_id):     return self.__get_static_field_val(emu, clazz_idx, field_id)
    @native_method
    def get_static_long_field(self, emu: "Emulator", env, clazz_idx, field_id):    return self.__get_static_field_val(emu, clazz_idx, field_id, "J")
    @native_method
    def get_static_float_field(self, emu: "Emulator", env, clazz_idx, field_id):   return self.__get_static_field_val(emu, clazz_idx, field_id, "F")
    @native_method
    def get_static_double_field(self, emu: "Emulator", env, clazz_idx, field_id):  return self.__get_static_field_val(emu, clazz_idx, field_id, "D")

    @native_method
    def set_static_object_field(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_static_boolean_field(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_static_byte_field(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_static_char_field(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_static_short_field(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_static_int_field(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def set_static_long_field(self, emu: "Emulator", env, clazz_idx, field_id, _, value_l, value_h):
        value = value_h << 32 | value_l
        clazz = self.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")
        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()
        field = pyclazz.find_field_by_id(field_id)
        field.static_value = value

    @native_method
    def set_static_float_field(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_static_double_field(self, emu: "Emulator", env): raise NotImplementedError()

    # =========================================================================
    # 6. STRINGS & ARRAYS
    # =========================================================================

    @native_method
    def new_string(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_string_length(self, emu: "Emulator", env, string):
        str_ref = self.get_reference(string)
        if not str_ref or str_ref.value == JAVA_NULL:
            return 0
        return len(str_ref.value.get_py_string())

    @native_method
    def get_string_chars(self, emu: "Emulator", env, string, is_copy_ptr):
        str_ref = self.get_reference(string)
        if not str_ref or str_ref.value == JAVA_NULL:
            return JAVA_NULL

        str_val = str_ref.value.get_py_string()
        utf16_bytes = str_val.encode("utf-16le") + b"\x00\x00"

        buf_ptr = self.__libc.malloc(len(utf16_bytes))
        emu.mu.mem_write(buf_ptr, utf16_bytes)

        if is_copy_ptr != 0:
            emu.mu.mem_write(is_copy_ptr, b"\x01")
        return buf_ptr

    @native_method
    def release_string_chars(self, emu: "Emulator", env, string, chars_ptr):
        if chars_ptr != 0:
            self.__libc.free(chars_ptr)

    @native_method
    def new_string_utf(self, emu: "Emulator", env, utf8_ptr):
        pystr = helpers.read_utf8(emu.mu, utf8_ptr)
        string = self._string(pystr)
        return self.add_local_reference(jobject(string))

    @native_method
    def get_string_utf_length(self, emu: "Emulator", env, string):
        str_ref = self.get_reference(string)
        if not str_ref or str_ref.value == JAVA_NULL:
            return 0
        return len(str_ref.value.get_py_string())

    @native_method
    def get_string_utf_chars(self, emu: "Emulator", env, string, is_copy_ptr):
        str_ref = self.get_reference(string)
        if not str_ref or str_ref.value == JAVA_NULL:
            return JAVA_NULL

        utf8_bytes = str_ref.value.get_py_string().encode("utf-8") + b"\x00"
        str_ptr = self.__libc.malloc(len(utf8_bytes))
        emu.mu.mem_write(str_ptr, utf8_bytes)

        if is_copy_ptr != 0:
            emu.mu.mem_write(is_copy_ptr, b"\x01")
        return str_ptr

    @native_method
    def release_string_utf_chars(self, emu: "Emulator", env, string, utf8_ptr):
        if utf8_ptr != 0:
            self.__libc.free(utf8_ptr)

    @native_method
    def get_string_region(self, emu: "Emulator", env, string, start, len_in, buf_ptr):
        str_ref = self.get_reference(string)
        if not str_ref or str_ref.value == JAVA_NULL:
            return
        sub = str_ref.value.get_py_string()[start : start + len_in]
        emu.mu.mem_write(buf_ptr, sub.encode("utf-16le"))

    @native_method
    def get_string_utf_region(self, emu: "Emulator", env, string, start, len_in, buf_ptr):
        str_ref = self.get_reference(string)
        if not str_ref or str_ref.value == JAVA_NULL:
            return
        sub = str_ref.value.get_py_string()[start : start + len_in]
        emu.mu.mem_write(buf_ptr, sub.encode("utf-8"))

    @native_method
    def get_string_critical(self, emu: "Emulator", env, string, is_copy_ptr):
        return self.get_string_chars(emu, env, string, is_copy_ptr)

    @native_method
    def release_string_critical(self, emu: "Emulator", env, string, chars_ptr):
        return self.release_string_chars(emu, env, string, chars_ptr)

    # Array Operations
    def __prim_array(self, array_idx: int, kind: str, func: str):
        pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        actual = getattr(pyobj, "jni_kind", None)
        if actual is not None and actual != kind:
            raise ValueError(f"{func} on {pyobj.jvm_name}, an array of {actual!r} elements")
        return pyobj

    @staticmethod
    def __region(func: str, array_len: int, start: int, length: int):
        start, length = _jint(start), _jint(length)
        if start < 0 or length < 0 or start + length > array_len:
            raise IndexError(
                f"ArrayIndexOutOfBoundsException: {func}(start={start}, length={length}) on an array of length {array_len}"
            )
        return start, length

    def __new_prim_array(self, kind: str, length: int):
        func = f"New{_PRIM_NAME[kind]}Array"
        length = _jint(length)
        if length < 0:
            raise ValueError(f"NegativeArraySizeException: {func}({length})")
        clazz = self._class_loader.find_class_by_name(f"[{kind}")
        if clazz is None:
            raise RuntimeError(f"{func}: class [{kind} is not registered")
        zero = 0.0 if kind in "FD" else 0
        return self.add_local_reference(jobject(clazz([zero] * length)))

    def __get_prim_region(self, emu: "Emulator", array_idx: int, start: int, length: int, buf_ptr: int, kind: str):
        func = f"Get{_PRIM_NAME[kind]}ArrayRegion"
        items = self.__prim_array(array_idx, kind, func).get_py_items()
        start, length = self.__region(func, len(items), start, length)
        if length == 0:
            return
        emu.mu.mem_write(buf_ptr, _pack_elements(kind, items[start:start + length]))

    def __set_prim_region(self, emu: "Emulator", array_idx: int, start: int, length: int, buf_ptr: int, kind: str):
        func = f"Set{_PRIM_NAME[kind]}ArrayRegion"
        pyobj = self.__prim_array(array_idx, kind, func)
        start, length = self.__region(func, len(pyobj.get_py_items()), start, length)
        if length == 0:
            return
        data = bytes(emu.mu.mem_read(buf_ptr, length * _PRIM_ELEMENT[kind][2]))
        _assign_region(pyobj, start, _unpack_elements(kind, data))

    # Get<T>ArrayElements / Release<T>ArrayElements keep the buffer layout of the byte[] versions:
    # an 8 byte header in front of the elements, so the pointer handed out is buf + 8 and free() gets elems - 8
    def __get_prim_elements(self, emu: "Emulator", array_idx: int, is_copy_ptr: int, kind: str):
        items = self.__prim_array(array_idx, kind, f"Get{_PRIM_NAME[kind]}ArrayElements").get_py_items()
        data = _pack_elements(kind, items)
        extra_n = 8

        buf = self.__libc.malloc(extra_n + len(data))
        emu.mu.mem_write(buf, len(items).to_bytes(4, "little"))
        if data:
            emu.mu.mem_write(buf + extra_n, data)
        if is_copy_ptr != JAVA_NULL:  # the buffer is always a copy: tell the caller (a NULL isCopy is allowed)
            emu.mu.mem_write(is_copy_ptr, bytes([JNI_TRUE]))
        return buf + extra_n

    def __release_prim_elements(self, emu: "Emulator", array_idx: int, elems: int, mode: int, kind: str):
        if elems == JAVA_NULL:
            return
        pyobj = self.__prim_array(array_idx, kind, f"Release{_PRIM_NAME[kind]}ArrayElements")
        mode = _jint(mode)
        if mode in (0, JNI_COMMIT):  # copy the buffer back into the array, in place
            count = len(pyobj.get_py_items())
            if count:
                data = bytes(emu.mu.mem_read(elems, count * _PRIM_ELEMENT[kind][2]))
                _assign_region(pyobj, 0, _unpack_elements(kind, data))
        if mode in (0, JNI_ABORT):  # free the buffer
            self.__libc.free(elems - 8)

    def __array_kind(self, array_idx: int) -> str:
        """The JNI type letter of the elements of the array (for the type-less *PrimitiveArrayCritical functions)."""
        pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        kind = getattr(pyobj, "jni_kind", None)
        if kind is None and isinstance(pyobj.get_py_items(), (bytes, bytearray)):
            kind = "B"
        if kind is None:
            raise ValueError(f"cannot tell the element type of {pyobj.jvm_name} (use one of the primitive array classes)")
        return kind

    @native_method
    def get_array_length(self, emu: "Emulator", env, array):
        obj = self.get_reference(array)
        pyobj = self.jobject_to_pyobject(obj)
        return len(pyobj)

    @native_method
    def new_object_array(self, emu: "Emulator", env, size, class_idx, obj_init):
        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = clazz.value.get_py_clazz()
        arr_item_cls_name = pyclazz.jvm_name

        pyarr = [JAVA_NULL] * size
        if obj_init != JAVA_NULL:
            pyarr[0] = self.jobject_to_pyobject(self.get_reference(obj_init))

        new_jvm_name = f"[{arr_item_cls_name}" if arr_item_cls_name.startswith("[") else f"[L{arr_item_cls_name};"
        pyarray_clazz = self._class_loader.find_class_by_name(new_jvm_name)
        if pyarray_clazz is None:
            raise RuntimeError(f"NewObjectArray: Class {new_jvm_name} not found")

        arr = pyarray_clazz(pyarr)
        return self.add_local_reference(jobject(arr))

    @native_method
    def get_object_array_element(self, emu: "Emulator", env, array_idx, item_idx):
        array_pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        pyobj_item = array_pyobj[item_idx]
        return JAVA_NULL if pyobj_item == JAVA_NULL else self.add_local_reference(jobject(pyobj_item))

    @native_method
    def set_object_array_element(self, emu: "Emulator", env, array_idx, index, obj_idx):
        array_pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        array_pyobj[index] = self.jobject_to_pyobject(self.get_reference(obj_idx))

    @native_method
    def new_boolean_array(self, emu: "Emulator", env, length):
        return self.__new_prim_array("Z", length)

    @native_method
    def new_byte_array(self, emu: "Emulator", env, bytelen):
        barr = bytearray([0] * bytelen)
        return self.add_local_reference(jobject(self._array(barr)))

    @native_method
    def new_char_array(self, emu: "Emulator", env, length):
        return self.__new_prim_array("C", length)
    @native_method
    def new_short_array(self, emu: "Emulator", env, length):
        return self.__new_prim_array("S", length)
    @native_method
    def new_int_array(self, emu: "Emulator", env, length):
        return self.__new_prim_array("I", length)
    @native_method
    def new_long_array(self, emu: "Emulator", env, length):
        return self.__new_prim_array("J", length)
    @native_method
    def new_float_array(self, emu: "Emulator", env, length):
        return self.__new_prim_array("F", length)
    @native_method
    def new_double_array(self, emu: "Emulator", env, length):
        return self.__new_prim_array("D", length)

    @native_method
    def get_boolean_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, "Z")

    @native_method
    def get_byte_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        items = pyobj.get_py_items()
        items_len = len(items)
        extra_n = 8

        buf = self.__libc.malloc(extra_n + items_len)
        emu.mu.mem_write(buf, items_len.to_bytes(4, "little"))
        if items_len:
            emu.mu.mem_write(buf + extra_n, bytes(items))
        if is_copy_ptr != JAVA_NULL:  # the buffer is always a copy: tell the caller (a NULL isCopy is allowed)
            emu.mu.mem_write(is_copy_ptr, bytes([JNI_TRUE]))
        return buf + extra_n

    @native_method
    def get_char_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, "C")
    @native_method
    def get_short_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, "S")
    @native_method
    def get_int_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, "I")
    @native_method
    def get_long_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, "J")
    @native_method
    def get_float_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, "F")
    @native_method
    def get_double_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, "D")

    @native_method
    def release_boolean_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        self.__release_prim_elements(emu, array_idx, elems, mode, "Z")

    @native_method
    def release_byte_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        if elems == JAVA_NULL:
            return
        pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        if mode in (0, JNI_COMMIT):
            items_len = len(pyobj.get_py_items())
            pyobj.pyobject[:] = emu.mu.mem_read(elems, items_len)
        if mode in (0, JNI_ABORT):
            self.__libc.free(elems - 8)

    @native_method
    def release_char_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        self.__release_prim_elements(emu, array_idx, elems, mode, "C")
    @native_method
    def release_short_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        self.__release_prim_elements(emu, array_idx, elems, mode, "S")
    @native_method
    def release_int_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        self.__release_prim_elements(emu, array_idx, elems, mode, "I")
    @native_method
    def release_long_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        self.__release_prim_elements(emu, array_idx, elems, mode, "J")
    @native_method
    def release_float_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        self.__release_prim_elements(emu, array_idx, elems, mode, "F")
    @native_method
    def release_double_array_elements(self, emu: "Emulator", env, array_idx, elems, mode):
        self.__release_prim_elements(emu, array_idx, elems, mode, "D")

    @native_method
    def get_boolean_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__get_prim_region(emu, array_idx, start, length, buf_ptr, "Z")

    @native_method
    def get_byte_array_region(self, emu: "Emulator", env, array_idx, start, len_in, buf_ptr):
        pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        barr = pyobj.get_py_items()
        start, length = _jint(start), _jint(len_in)
        if start < 0 or length < 0 or start + length > len(barr):
            raise IndexError(
                f"ArrayIndexOutOfBoundsException: GetByteArrayRegion(start={start}, length={length}) "
                f"on an array of length {len(barr)}"
            )
        if length == 0:
            return
        emu.mu.mem_write(buf_ptr, bytes(barr[start : start + length]))

    @native_method
    def get_char_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__get_prim_region(emu, array_idx, start, length, buf_ptr, "C")
    @native_method
    def get_short_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__get_prim_region(emu, array_idx, start, length, buf_ptr, "S")
    @native_method
    def get_int_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__get_prim_region(emu, array_idx, start, length, buf_ptr, "I")
    @native_method
    def get_long_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__get_prim_region(emu, array_idx, start, length, buf_ptr, "J")
    @native_method
    def get_float_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__get_prim_region(emu, array_idx, start, length, buf_ptr, "F")
    @native_method
    def get_double_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__get_prim_region(emu, array_idx, start, length, buf_ptr, "D")

    @native_method
    def set_boolean_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__set_prim_region(emu, array_idx, start, length, buf_ptr, "Z")

    @native_method
    def set_byte_array_region(self, emu: "Emulator", env, arrayJREF, startIndex, length, bufAddress):
        # Copies buf into array[start:start+length] IN PLACE (like release_byte_array_elements does):
        # the Java object stays the same one for everybody who holds it, and the rest of the array
        # is kept. It used to replace the whole array by a new one made of the region only.
        pyobj = self.jobject_to_pyobject(self.get_reference(arrayJREF))
        items = pyobj.get_py_items()
        start, length = _jint(startIndex), _jint(length)
        if start < 0 or length < 0 or start + length > len(items):
            raise IndexError(
                f"ArrayIndexOutOfBoundsException: SetByteArrayRegion(start={start}, length={length}) "
                f"on an array of length {len(items)}"
            )
        if length == 0:
            return

        data = helpers.read_byte_array(emu.mu, bufAddress, length)
        if isinstance(items, (bytes, tuple)): # immutable backing store: swap it, keep the Java object
            items = bytearray(items)
            pyobj.pyobject = items
        items[start:start + length] = data

    @native_method
    def set_char_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__set_prim_region(emu, array_idx, start, length, buf_ptr, "C")
    @native_method
    def set_short_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__set_prim_region(emu, array_idx, start, length, buf_ptr, "S")
    @native_method
    def set_int_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__set_prim_region(emu, array_idx, start, length, buf_ptr, "I")
    @native_method
    def set_long_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__set_prim_region(emu, array_idx, start, length, buf_ptr, "J")
    @native_method
    def set_float_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__set_prim_region(emu, array_idx, start, length, buf_ptr, "F")
    @native_method
    def set_double_array_region(self, emu: "Emulator", env, array_idx, start, length, buf_ptr):
        self.__set_prim_region(emu, array_idx, start, length, buf_ptr, "D")

    @native_method
    def get_primitive_array_critical(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        kind = self.__array_kind(array_idx)
        if kind == "B":
            return self.get_byte_array_elements(emu, env, array_idx, is_copy_ptr)
        return self.__get_prim_elements(emu, array_idx, is_copy_ptr, kind)

    @native_method
    def release_primitive_array_critical(self, emu: "Emulator", env, array_idx, elems, mode):
        kind = self.__array_kind(array_idx)
        if kind == "B":
            return self.release_byte_array_elements(emu, env, array_idx, elems, mode)
        return self.__release_prim_elements(emu, array_idx, elems, mode, kind)

    # =========================================================================
    # 7. OBJECT LIFECYCLE, CLASSES & REFLECTION
    # =========================================================================

    @native_method
    def get_version(self, emu: "Emulator", env) -> int:
        return JNI_VERSION_1_6

    @native_method
    def define_class(self, emu: "Emulator", env) -> int:
        raise NotImplementedError()

    @native_method
    def find_class(self, emu: "Emulator", env, name_ptr) -> int:
        name = helpers.read_utf8(emu.mu, name_ptr)
        pyclazz = self._class_loader.find_class_by_name(name)
        if pyclazz is None:
            raise RuntimeError(f"Could not find class '{name}' for JNIEnv.")
        if pyclazz.jvm_ignore:
            return 0
        return self.add_local_reference(jclass(pyclazz.class_object))

    @native_method
    def get_superclass(self, emu: "Emulator", env, clazz_idx) -> int:
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError(f"Expected a jclass on {clazz_idx}.")
        pyclass = jclazz.value.get_py_clazz()
        if not pyclass.jvm_super:
            raise RuntimeError(f"Super class for {pyclass} is None! Must inherit Object.")
        return self.add_local_reference(jclass(pyclass.jvm_super.class_object))

    @native_method
    def is_assignable_from(self, emu: "Emulator", env, clazz_idx1, clazz_idx2) -> int:
        pyclass1 = self.get_reference(clazz_idx1).value.get_py_clazz()
        pyclass2 = self.get_reference(clazz_idx2).value.get_py_clazz()

        jvm_super = pyclass1.jvm_super
        while jvm_super is not None:
            if jvm_super == pyclass2:
                return JNI_TRUE
            jvm_super = jvm_super.jvm_super
        return JNI_FALSE

    @native_method
    def is_instance_of(self, emu: "Emulator", env, obj_idx, class_idx):
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = clazz.value.get_py_clazz()
        pyobj = self.jobject_to_pyobject(obj)
        return JNI_TRUE if pyobj.jvm_id == pyclazz.jvm_id else JNI_FALSE

    @native_method
    def is_same_object(self, emu: "Emulator", env, ref1, ref2):
        if ref1 == 0 and ref2 == 0: return JNI_TRUE
        if ref1 == 0 or ref2 == 0:  return JNI_FALSE
        pyobj1 = self.jobject_to_pyobject(self.get_reference(ref1))
        pyobj2 = self.jobject_to_pyobject(self.get_reference(ref2))
        return JNI_TRUE if pyobj1 is pyobj2 else JNI_FALSE

    @native_method
    def get_object_class(self, emu: "Emulator", env, obj_idx):
        obj = self.get_reference(obj_idx)
        if obj is None:
            raise RuntimeError(f"get_object_class: cannot get class for obj_id {obj_idx}")
        pyobj = self.jobject_to_pyobject(obj)
        return self.add_local_reference(jclass(pyobj.__class__.class_object))

    @native_method
    def get_method_id(self, emu: "Emulator", env, clazz_idx, name_ptr, sig_ptr):
        name = helpers.read_utf8(emu.mu, name_ptr)
        sig = helpers.read_utf8(emu.mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = clazz.value.get_py_clazz()
        method = pyclazz.find_method(name, sig)
        if method is None:
            raise RuntimeError(f"Could not find method ('{name}', '{sig}') in class {pyclazz.jvm_name}.")
        return method.jvm_id

    @native_method
    def get_static_method_id(self, emu: "Emulator", env, clazz_idx, name_ptr, sig_ptr):
        name = helpers.read_utf8(emu.mu, name_ptr)
        sig = helpers.read_utf8(emu.mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = clazz.value.get_py_clazz()
        method = pyclazz.find_method(name, sig)
        if method is None:
            raise RuntimeError(f"Could not find static method ('{name}', '{sig}') in class {pyclazz.jvm_name}.")
        return 0 if method.ignore else method.jvm_id

    # Constructors & Instances
    def __create_instance(self, emu: "Emulator", clazz_idx: int, method_id: int, args, args_type: int):
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = jclazz.value.get_py_clazz()
        obj = pyclazz()

        method = pyclazz.find_method_by_id(method_id)
        if method.name != "<init>" or not method.signature.endswith("V"):
            raise ValueError("Class constructor has the wrong name or does not return void.")

        constructor_args = self.__read_args_common(emu, args, method.args_list, args_type)
        method.func(obj, emu, *constructor_args)
        return self.add_local_reference(jobject(obj))

    @native_method
    def new_object(self, emu: "Emulator", env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__create_instance(emu, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    @native_method
    def new_object_v(self, emu: "Emulator", env, clazz_idx, method_id, args_v):
        return self.__create_instance(emu, clazz_idx, method_id, args_v, 1)

    @native_method
    def new_object_a(self, emu: "Emulator", env, clazz_idx, method_id, args_a):
        return self.__create_instance(emu, clazz_idx, method_id, args_a, 2)
    @native_method
    def alloc_object(self, emu: "Emulator", env, clazz_idx):
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")
        obj = _allocate_py_instance(jclazz.value.get_py_clazz())
        return self.add_local_reference(jobject(obj))

    # Reflection Bridging
    @native_method
    def from_reflected_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def from_reflected_field(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def to_reflected_field(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def to_reflected_method(self, emu: "Emulator", env, class_idx, method_id, is_static):
        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")
        pyclazz = clazz.value.get_py_clazz()
        method_def = pyclazz.find_method_by_id(method_id)
        if method_def is None:
            raise RuntimeError(f"Could not find method ('{method_id}') in class {pyclazz.jvm_name}.")

        if method_def.name == "<init>" and method_def.signature.endswith("V"):
            constructor_cls = self._class_loader.find_class_by_name("java/lang/reflect/Constructor")
            res_obj = constructor_cls(pyclazz, method_def)
        else:
            method_cls = self._class_loader.find_class_by_name("java/lang/reflect/Method")
            res_obj = method_cls(pyclazz, method_def)
        return self.add_local_reference(jobject(res_obj))

    # =========================================================================
    # 8. REFERENCES, NATIVES & VM CONTROL
    # =========================================================================

    @native_method
    def new_local_ref(self, emu: "Emulator", env, ref):
        obj = self.get_reference(ref)
        return 0 if obj is None else self.add_local_reference(obj)

    @native_method
    def delete_local_ref(self, emu: "Emulator", env, idx):
        if idx != 0:
            self.delete_local_reference(self.get_local_reference(idx))

    @native_method
    def ensure_local_capacity(self, emu: "Emulator", env):
        return JNI_OK

    @native_method
    def push_local_frame(self, emu: "Emulator", env, capacity):
        return 0

    @native_method
    def pop_local_frame(self, emu: "Emulator", env, result_jobj):
        return result_jobj

    @native_method
    def new_global_ref(self, emu: "Emulator", env, jobj):
        if jobj == 0:
            return 0
        obj = self.get_reference(jobj)
        if obj is None:
            raise NotImplementedError("Invalid local reference obj.")
        return self.add_global_reference(obj)

    @native_method
    def delete_global_ref(self, emu: "Emulator", env, idx):
        if idx != 0:
            self.delete_global_reference(self.get_global_reference(idx))

    @native_method
    def new_weak_global_ref(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def delete_weak_global_ref(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_object_ref_type(self, emu: "Emulator", env):
        return JNI_InvalidRefType

    # Exceptions
    @native_method
    def throw(self, emu: "Emulator", env): raise RuntimeError("JNI throw() called")
    @native_method
    def throw_new(self, emu: "Emulator", env): raise RuntimeError("JNI throw_new() called")
    @native_method
    def exception_occurred(self, emu: "Emulator", env): return 0
    @native_method
    def exception_describe(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def exception_clear(self, emu: "Emulator", env): return None
    @native_method
    def exception_check(self, emu: "Emulator", env): return JNI_FALSE
    @native_method
    def fatal_error(self, emu: "Emulator", env): raise NotImplementedError()

    # Native registration & VM
    @native_method
    def register_natives(self, emu: "Emulator", env, clazz_id, methods, methods_count):
        clazz = self.get_reference(clazz_id)
        if not isinstance(clazz, jclass):
            raise ValueError(f"Expected a jclass but got {type(clazz)}.")

        pyclazz = clazz.value.get_py_clazz()
        ptr_sz = ptr_t.size

        for i in range(methods_count):
            base_off = (i * 3 * ptr_sz) + methods
            ptr_name = helpers.read_ptr_sz(emu.mu, base_off)
            ptr_sign = helpers.read_ptr_sz(emu.mu, base_off + ptr_sz)
            ptr_func = helpers.read_ptr_sz(emu.mu, base_off + 2 * ptr_sz)

            name = helpers.read_utf8(emu.mu, ptr_name)
            signature = helpers.read_utf8(emu.mu, ptr_sign)

            logging.info(f"Registered native function {name} ({signature}) at {hex(ptr_func)}")
            pyclazz.register_native(name, signature, ptr_func)
        return JNI_OK

    @native_method
    def unregister_natives(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def monitor_enter(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def monitor_exit(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_java_vm(self, emu: "Emulator", env, vm):
        emu.mu.mem_write(vm, emu.java_vm.address_ptr.to_bytes(ptr_t.size, byteorder="little"))
        return JNI_OK

    # Direct Byte Buffers
    @native_method
    def new_direct_byte_buffer(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_direct_buffer_address(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_direct_buffer_capacity(self, emu: "Emulator", env): raise NotImplementedError()