import inspect
import logging
from .jvm_id_conter import *

from typing import TYPE_CHECKING, Dict
if TYPE_CHECKING:
    from .java_class_def import JavaClassDef
    from .java_method_def import JavaMethodDef
    from .java_field_def import JavaFieldDef

logger = logging.getLogger(__name__)

class JavaClassDef(type):
    """
    Class Function Implementation Guidelines:

    Python functions (including __init__): Use native Python types (e.g., str, int) for all inputs and outputs.

    Simulated Java functions (@java_method_def): Use Java types (e.g., String, Integer) for all inputs and outputs, except for the 8 primitive types. Note: Distinguish Integer (object) from int (primitive).

    Primitive return types: Map Java integers to Python int, and Java float/double to Python float.
    """
    
    def __init__(cls, name, base, ns, jvm_name=None, jvm_fields=None, jvm_ignore=False, jvm_super=None):
        cls.jvm_id:         int                         = next_cls_id()
        cls.jvm_name:       str                         = jvm_name
        cls.jvm_methods:    Dict[int, 'JavaMethodDef']  = dict()
        cls.jvm_fields:     Dict[int, 'JavaFieldDef']   = dict()
        cls.jvm_ignore:     bool                        = jvm_ignore
        cls.jvm_super:      'JavaClassDef'              = jvm_super
        cls.class_object:   'JavaClassDef'              = None

        # Register all defined Java methods.
        for func in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(func[1], 'jvm_method'):
                method = func[1].jvm_method
                cls.jvm_methods[method.jvm_id] = method

        # Register all defined Java fields.
        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                cls.jvm_fields[jvm_field.jvm_id] = jvm_field
        type.__init__(cls, name, base, ns)

    def __new__(cls, name, base, ns, **kargs):
        return type.__new__(cls, name, base, ns)

    def register_native(cls, name, signature, ptr_func) -> None:
        found = False

        # Search for a defined jvm method.
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                found = True
                break

        if not found:
            x = "Register native ('%s', '%s', '0x%08X') failed on class %s." % (name, signature, ptr_func, cls.__name__)
            return
            # raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, cls.__name__))
    
    def find_method(cls, name: str, signature: str) -> 'JavaMethodDef':
        """
        Find a PyMethod by its name and signature

        :param name: Name
        :param signature: Signature
        :return: PyMethod
        """
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                return method
        if (cls.jvm_super is not None):
            return cls.jvm_super.find_method(name, signature)
        return None

    def find_method_sig_with_no_ret(cls, name, signature_no_ret) -> None:
        """
        Used to support Java reflection; Java reflection signatures have no return values.
        @param signature_no_ret: something like (ILjava/lang/String;).
        """
        assert signature_no_ret[0] == "(" and signature_no_ret[len(signature_no_ret)-1] == ")", "signature_no_ret error"
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature.startswith(signature_no_ret):
                return method

        if (cls.jvm_super is not None):
            return cls.jvm_super.find_method_sig_with_no_ret(name, signature_no_ret)
        return None


    def find_method_by_id(cls, jvm_id: int) -> 'JavaMethodDef':
        """
        Find a PyMethod by its ID

        :param jvm_id: ID
        :return: PyMethod
        """
        if (jvm_id in cls.jvm_methods):
            return cls.jvm_methods[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_method_by_id(jvm_id)
        return None

    def find_field(cls, name: str, signature: str, is_static: bool) -> 'JavaFieldDef':
        """
        Find a PyField by its name and signature

        :param name: Name
        :param signature: Signature
        :return: PyField
        """
        for field in cls.jvm_fields.values():
            if field.name == name and field.signature == signature and field.is_static == is_static:
                return field

        if (cls.jvm_super is not None):
            return cls.jvm_super.find_field(name, signature, is_static)

        return None

    def find_field_by_id(cls, jvm_id: int) -> 'JavaFieldDef':
        """
        Find a PyField by its ID

        :param jvm_id: ID
        :return: PyField
        """
        if (jvm_id in cls.jvm_fields):
            return cls.jvm_fields[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_field_by_id(jvm_id)
        return None