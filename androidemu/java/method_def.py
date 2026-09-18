import sys

from typing import List, Optional, Callable, TYPE_CHECKING

from .class_def import JavaClassDef
from .jni.reference import *
from ..const import emu_const

from .jvm.id_counter import next_method_id
from .jvm.constants import JAVA_NULL

if TYPE_CHECKING:
    from ..core.emulator import Emulator

class JavaMethodDef:
    """
    Define a java method
    """

    __slots__ = (
        "jvm_id",
        "func_name",
        "func",
        "name",
        "signature",
        "native",
        "native_addr",
        "args_list",
        "modifier",
        "ignore",
    )

    def __init__(
        self,
        func_name: str,
        func: Optional[Callable],
        name: str,
        signature: str,
        native: bool,
        args_list: Optional[List[str]] = None,
        modifier: Optional[int] = None,
        ignore: bool = False,
    ):
        self.jvm_id = next_method_id()
        self.func_name = func_name
        self.func = func
        self.name = name
        self.signature = signature
        self.native = native
        self.native_addr = None
        self.args_list = args_list
        self.modifier = modifier
        self.ignore = ignore

def java_method_def(name: str, signature: str, native: bool=False, args_list: List=None, modifier: int=None, ignore: bool=False) -> callable:
    """
    Decorator!
    
    Register a python function as a java method

    :param name: Name
    :param signature: Signature
    :param native: Is native
    :param args_list: Args list
    :param modifier: Modifier
    :param ignore: Ignore
    """
    def java_method_def_real(func): # oh my fucking god

        def native_wrapper(*args, **kwargs):
            clz = args[0].__class__
            emulator: 'Emulator' = None
            extra_args: List = None
            first_obj: int = 0xFA # dummy-value. If you see it - there is a trouble...
            
            # for java-like code style.
            if (isinstance(clz, JavaClassDef)):
                # If no @staticmethod
                emulator = args[1]
                extra_args = args[2:] # other shi

                # providing a reference to the class object
                first_obj = emulator.java_vm.jni_env.add_local_reference(jobject(args[0]))
            else:
                #if it's @staticmethod
                emulator = args[0]
                extra_args = args[1:]

                # first param of static method is jclass. We need to find the pyclass and convert it to jclass
                vals = vars(sys.modules[func.__module__])
                sa = func.__qualname__.split(".") #workable shi

                # layer by layer iterator for nested class
                for attr in sa[:-1]:
                    vals = vals[attr]

                clsname = sa[-1]
                pyclazz = vals
                if (not isinstance(pyclazz, JavaClassDef)): # so what's you doin here brotha
                    raise RuntimeError("Error class %s is not register as jvm class!!!"%clsname)

                jvm_clazz = pyclazz.class_object
                # providing a reference to the class object
                first_obj = emulator.java_vm.jni_env.add_local_reference(jclass(jvm_clazz))

            brace_index = signature.find(")")
            if (brace_index < 0):
                raise RuntimeError("native_wrapper invalid function signature %s"%signature)

            return_index = brace_index + 1
            return_ch = signature[return_index]
            res = None
            arch = emulator.arch
            if (return_ch in ('J', 'D') and arch == emu_const.ARCH_ARM32):
                # value in jlong or jdoube. So we read the value from 2 registers.
                res = emulator.call_native_return_2reg(
                    native_wrapper.jvm_method.native_addr,
                    emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                    first_obj,                             # this object or this class
                                                           # method has been declared in
                    *extra_args                            # Extra args.
                )
            else:
                res = emulator.call_native(
                    native_wrapper.jvm_method.native_addr,
                    emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                    first_obj,                             # this object or this class
                                                           # method has been declared in
                    *extra_args                            # Extra args.
                )

            final_result = None
            if (return_ch in ('[', 'L')):
                # reading JNIRef for providing already object.
                result_idx = res
                result = emulator.java_vm.jni_env.get_local_reference(result_idx)
                if result is None:
                    final_result = JAVA_NULL
                else:
                    final_result = result.value

            else:
                # base types is not jobject
                final_result = res

            # jni specifically says that the local references must be cleared when we exit a native method
            emulator.java_vm.jni_env.clear_locals()
            return final_result

        def normal_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return result

        wrapper = native_wrapper if native else normal_wrapper
        wrapper.jvm_method = JavaMethodDef(func.__name__, wrapper, name, signature, native,
                                           args_list=args_list,
                                           modifier=modifier,
                                           ignore=ignore)
        return wrapper
    
    return java_method_def_real