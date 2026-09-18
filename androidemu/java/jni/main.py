import logging
import struct
from typing import TYPE_CHECKING, List, Optional

from unicorn import *

from ...const import emu_const
from ..jvm.constants import JAVA_NULL, MODIFIER_STATIC
from .constants import *
from .reference import jobject, jclass
from ..reference_table import ReferenceTable
from ...native.helpers.jni_native import (
    read_args32, read_args64,
    read_args_v32, read_args_v64
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


class JNIEnv:
    """
    Simulated JNIEnv (JNINativeInterface).
    """

    # =========================================================================
    # 1. INTERNAL HELPERS & CALL DISPATCHER
    # =========================================================================

    def __read_args_common(self, emu: "Emulator", args, args_type_list, arg_type: int) -> List:
        if arg_type == 0:
            return self.__read_args(self, emu.mu, args, args_type_list)
        elif arg_type == 1:
            return self.__read_args_v(self, emu.mu, args, args_type_list)
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

    def __dyncall(self, emu: "Emulator", is_static: bool, is_wide: bool = False):
        regs = emu.registers
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

        n_args = len(method.args_list) if method.args_list else 0
        raw_call_args = regs.read_args(3 + n_args)[3:]
        call_args = self.__read_args_common(emu, raw_call_args, method.args_list, arg_type=0)

        if is_static:
            v = method.func(emu, *call_args)
        else:
            real_method = clazz.find_method(method.name, method.signature)
            v = real_method.func(target_instance, emu, *call_args)

        if not is_wide:
            if v is not None and not isinstance(v, (int, float, bool)):
                return self.add_local_reference(jobject(v))
            return v
        else:
            if isinstance(v, float):
                raw_bits = struct.unpack("<Q", struct.pack("<d", v))[0]
            else:
                raw_bits = int(v) & 0xFFFFFFFFFFFFFFFF
            return (raw_bits & 0xFFFFFFFF, raw_bits >> 32)

    def __dispatch_call(self, emu: "Emulator", is_static: bool, is_wide: bool = False):
        res = self.__dyncall(emu, is_static, is_wide)
        if res is not None:
            if is_wide:
                rlow, rhigh = res
                emu.registers.v_reg_0 = rlow
                emu.registers.v_reg_1 = rhigh
            else:
                emu.registers.v_reg_0 = res

    def __call_varargs_method(self, emu: "Emulator", env, obj_idx: int, method_id: int, args_v, is_wide: bool = False):
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = self.jobject_to_pyobject(obj)

        clazz: "JavaClassDef" = pyobj.__class__

        method = clazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(f"Could not find method {method_id} in object by id.")

        constructor_args = self.__read_args_common(emu, args_v, method.args_list, arg_type=1)
        real_method = clazz.find_method(method.name, method.signature)
        v = real_method.func(pyobj, emu, *constructor_args)

        if not is_wide:
            return v
        rhigh = v >> 32
        rlow = v & 0xFFFFFFFF
        return (rlow, rhigh)

    def __call_static_varargs_method(self, emu: "Emulator", env, clazz_idx: int, method_id: int, args_v, is_wide: bool = False):
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

        if not is_wide:
            return v
        raw_bits = struct.unpack("<Q", struct.pack("<d", v))[0]
        return (raw_bits & 0xFFFFFFFF, raw_bits >> 32)

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
        elif arch == emu_const.ARCH_ARM64:
            self.__read_args = read_args64
            self.__read_args_v = read_args_v64
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

    def call_object_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=False, is_wide=False)
    def call_boolean_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=False, is_wide=False)
    def call_byte_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False, is_wide=False)
    def call_char_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False, is_wide=False)
    def call_short_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=False, is_wide=False)
    def call_int_method(self, emu: "Emulator"):     self.__dispatch_call(emu, is_static=False, is_wide=False)
    def call_long_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False, is_wide=True)
    def call_float_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=False, is_wide=False)
    def call_double_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=False, is_wide=True)
    def call_void_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=False, is_wide=False)

    def call_static_object_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=True, is_wide=False)
    def call_static_boolean_method(self, emu: "Emulator"): self.__dispatch_call(emu, is_static=True, is_wide=False)
    def call_static_byte_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True, is_wide=False)
    def call_static_char_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True, is_wide=False)
    def call_static_short_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=True, is_wide=False)
    def call_static_int_method(self, emu: "Emulator"):     self.__dispatch_call(emu, is_static=True, is_wide=False)
    def call_static_long_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True, is_wide=True)
    def call_static_float_method(self, emu: "Emulator"):   self.__dispatch_call(emu, is_static=True, is_wide=False)
    def call_static_double_method(self, emu: "Emulator"):  self.__dispatch_call(emu, is_static=True, is_wide=True)
    def call_static_void_method(self, emu: "Emulator"):    self.__dispatch_call(emu, is_static=True, is_wide=False)

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
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, True)

    @native_method
    def call_float_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, False)

    @native_method
    def call_double_method_v(self, emu: "Emulator", env, obj_idx, method_id, args):
        return self.__call_varargs_method(emu, env, obj_idx, method_id, args, True)

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
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, True)

    @native_method
    def call_static_float_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    @native_method
    def call_static_double_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        return self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, True)

    @native_method
    def call_static_void_method_v(self, emu: "Emulator", env, clazz_idx, method_id, args):
        self.__call_static_varargs_method(emu, env, clazz_idx, method_id, args, False)

    # Stubbed _a variants
    @native_method
    def call_object_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_boolean_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_byte_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_char_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_short_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_int_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_long_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_float_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_double_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_void_method_a(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def call_static_object_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_boolean_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_byte_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_char_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_short_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_int_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_long_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_float_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_double_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_static_void_method_a(self, emu: "Emulator", env): raise NotImplementedError()

    # Nonvirtual stubs
    @native_method
    def call_nonvirtual_object_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_object_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_object_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_boolean_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_boolean_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_boolean_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_byte_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_byte_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_byte_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_char_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_char_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_char_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_short_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_short_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_short_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_int_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_int_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_int_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_long_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_long_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_long_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_float_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_float_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_float_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_double_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_double_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_double_method_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_void_method(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_void_method_v(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def call_nonvirtual_void_method_a(self, emu: "Emulator", env): raise NotImplementedError()

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

    def __get_field_val(self, emu: "Emulator", obj_idx: int, field_id: int, is_wide: bool = False):
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = self.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)
        if field is None:
            raise RuntimeError(f"Could not find field {field_id} in object {pyobj.jvm_name} by id.")

        v = getattr(pyobj, field.name)
        if not is_wide:
            return v
        return (v & 0xFFFFFFFF, v >> 32)

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
    def get_long_field(self, emu: "Emulator", env, obj_idx, field_id):    return self.__get_field_val(emu, obj_idx, field_id, is_wide=True)
    @native_method
    def get_float_field(self, emu: "Emulator", env, obj_idx, field_id):   return self.__get_field_val(emu, obj_idx, field_id)
    @native_method
    def get_double_field(self, emu: "Emulator", env, obj_idx, field_id):  raise NotImplementedError()

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

    def __get_static_field_val(self, clazz_idx: int, field_id: int, is_wide: bool = False):
        clazz = self.get_reference(clazz_idx)
        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)
        v = field.static_value
        if not is_wide:
            return v
        return (v & 0xFFFFFFFF, v >> 32)

    @native_method
    def get_static_object_field(self, emu: "Emulator", env, clazz_idx, field_id):  return self.__get_static_field_val(clazz_idx, field_id)
    @native_method
    def get_static_boolean_field(self, emu: "Emulator", env, clazz_idx, field_id): return self.__get_static_field_val(clazz_idx, field_id)
    @native_method
    def get_static_byte_field(self, emu, env, clazz_idx, field_id):                return self.__get_static_field_val(clazz_idx, field_id)
    @native_method
    def get_static_char_field(self, emu: "Emulator", env, clazz_idx, field_id):    return self.__get_static_field_val(clazz_idx, field_id)
    @native_method
    def get_static_short_field(self, emu: "Emulator", env, clazz_idx, field_id):   return self.__get_static_field_val(clazz_idx, field_id)
    @native_method
    def get_static_int_field(self, emu: "Emulator", env, clazz_idx, field_id):     return self.__get_static_field_val(clazz_idx, field_id)
    @native_method
    def get_static_long_field(self, emu: "Emulator", env, clazz_idx, field_id):    return self.__get_static_field_val(clazz_idx, field_id, is_wide=True)
    @native_method
    def get_static_float_field(self, emu: "Emulator", env, clazz_idx, field_id):   return self.__get_static_field_val(clazz_idx, field_id)
    @native_method
    def get_static_double_field(self, emu: "Emulator", env, clazz_idx, field_id):  return self.__get_static_field_val(clazz_idx, field_id, is_wide=True)

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
    def new_boolean_array(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def new_byte_array(self, emu: "Emulator", env, bytelen):
        barr = bytearray([0] * bytelen)
        return self.add_local_reference(jobject(self._array(barr)))

    @native_method
    def new_char_array(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def new_short_array(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def new_int_array(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def new_long_array(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def new_float_array(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def new_double_array(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_boolean_array_elements(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_byte_array_elements(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        if is_copy_ptr != 0:
            raise NotImplementedError()
        pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        items = pyobj.get_py_items()
        items_len = len(items)
        extra_n = 8

        buf = self.__libc.malloc(extra_n + items_len)
        emu.mu.mem_write(buf, items_len.to_bytes(4, "little"))
        emu.mu.mem_write(buf + extra_n, bytes(items))
        return buf + extra_n

    @native_method
    def get_char_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_short_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_int_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_long_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_float_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_double_array_elements(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def release_boolean_array_elements(self, emu: "Emulator", env): raise NotImplementedError()

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
    def release_char_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def release_short_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def release_int_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def release_long_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def release_float_array_elements(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def release_double_array_elements(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_boolean_array_region(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_byte_array_region(self, emu: "Emulator", env, array_idx, start, len_in, buf_ptr):
        pyobj = self.jobject_to_pyobject(self.get_reference(array_idx))
        barr = pyobj.get_py_items()
        emu.mu.mem_write(buf_ptr, bytes(barr[start : start + len_in]))

    @native_method
    def get_char_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_short_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_int_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_long_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_float_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def get_double_array_region(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def set_boolean_array_region(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def set_byte_array_region(self, emu: "Emulator", env, arrayJREF, startIndex, length, bufAddress):
        string = helpers.read_byte_array(emu.mu, bufAddress, length)
        self.set_local_reference(arrayJREF, jobject(self._array(string)))

    @native_method
    def set_char_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_short_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_int_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_long_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_float_array_region(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def set_double_array_region(self, emu: "Emulator", env): raise NotImplementedError()

    @native_method
    def get_primitive_array_critical(self, emu: "Emulator", env, array_idx, is_copy_ptr):
        return self.get_byte_array_elements(emu, env, array_idx, is_copy_ptr)

    @native_method
    def release_primitive_array_critical(self, emu: "Emulator", env, array_idx, elems, mode):
        return self.release_byte_array_elements(emu, env, array_idx, elems, mode)

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
    def new_object_a(self, emu: "Emulator", env): raise NotImplementedError()
    @native_method
    def alloc_object(self, emu: "Emulator", env): raise NotImplementedError()

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