import logging
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Any
from .jvm.id_counter import next_cls_id

if TYPE_CHECKING:
    from .method_def import JavaMethodDef
    from .field_def import JavaFieldDef

logger = logging.getLogger(__name__)


class JavaClassDef(type):
    def __new__(cls, name: str, bases: Tuple[type, ...], ns: Dict[str, Any], **kwargs: Any):
        return type.__new__(cls, name, bases, ns)

    def __init__(
        cls,
        name: str,
        bases: Tuple[type, ...],
        ns: Dict[str, Any],
        jvm_name: Optional[str] = None,
        jvm_fields: Optional[List['JavaFieldDef']] = None,
        jvm_ignore: bool = False,
        jvm_super: Optional['JavaClassDef'] = None,
        jvm_interfaces: Optional[List['JavaClassDef']] = None,
        **kwargs: Any,
    ):
        cls.jvm_id: int = next_cls_id()
        cls.jvm_name: str = jvm_name or name.replace('.', '/')
        cls.jvm_methods: Dict[int, 'JavaMethodDef'] = {}
        cls.jvm_fields: Dict[int, 'JavaFieldDef'] = {}
        cls.jvm_ignore: bool = jvm_ignore
        cls.class_object: Any = None
        cls.jvm_interfaces: List['JavaClassDef'] = jvm_interfaces or []

        if jvm_super is not None:
            cls.jvm_super = jvm_super
        else:
            cls.jvm_super = None
            for b in bases:
                if isinstance(b, JavaClassDef) and getattr(b, 'jvm_name', '') != 'java/lang/Object':
                    cls.jvm_super = b
                    break
            if cls.jvm_super is None and cls.jvm_name != 'java/lang/Object':
                for b in bases:
                    if isinstance(b, JavaClassDef) and getattr(b, 'jvm_name', '') == 'java/lang/Object':
                        cls.jvm_super = b
                        break

        cls._name_sig_cache: Dict[Tuple[str, str], 'JavaMethodDef'] = {}

        for member_name, member_obj in ns.items():
            real_obj = member_obj
            if isinstance(member_obj, staticmethod):
                real_obj = member_obj.__func__

            if hasattr(real_obj, 'jvm_method'):
                method: 'JavaMethodDef' = real_obj.jvm_method
                cls.jvm_methods[method.jvm_id] = method
                cls._name_sig_cache[(method.name, method.signature)] = method

        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                cls.jvm_fields[jvm_field.jvm_id] = jvm_field

        type.__init__(cls, name, bases, ns)

    def register_native(cls, name: str, signature: str, ptr_func: int) -> None:
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                return

        from .method_def import JavaMethodDef
        method = JavaMethodDef(name, None, name, signature, native=True)
        method.native_addr = ptr_func
        cls.jvm_methods[method.jvm_id] = method
        cls._name_sig_cache[(name, signature)] = method

    def find_method(cls, name: str, signature: str) -> Optional['JavaMethodDef']:
        method = cls._name_sig_cache.get((name, signature))
        if method is not None:
            return method

        if cls.jvm_super is not None:
            m = cls.jvm_super.find_method(name, signature)
            if m is not None:
                return m

        for iface in cls.jvm_interfaces:
            m = iface.find_method(name, signature)
            if m is not None:
                return m

        return None

    def find_method_sig_with_no_ret(cls, name: str, signature_no_ret: str) -> Optional['JavaMethodDef']:
        assert signature_no_ret.startswith("(") and signature_no_ret.endswith(")"), "signature_no_ret error"
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature.startswith(signature_no_ret):
                return method

        if cls.jvm_super is not None:
            m = cls.jvm_super.find_method_sig_with_no_ret(name, signature_no_ret)
            if m is not None:
                return m

        for iface in cls.jvm_interfaces:
            m = iface.find_method_sig_with_no_ret(name, signature_no_ret)
            if m is not None:
                return m

        return None

    def find_method_by_id(cls, jvm_id: int) -> Optional['JavaMethodDef']:
        if jvm_id in cls.jvm_methods:
            return cls.jvm_methods[jvm_id]

        if cls.jvm_super is not None:
            m = cls.jvm_super.find_method_by_id(jvm_id)
            if m is not None:
                return m

        for iface in cls.jvm_interfaces:
            m = iface.find_method_by_id(jvm_id)
            if m is not None:
                return m

        return None

    def find_field(cls, name: str, signature: str, is_static: bool) -> Optional['JavaFieldDef']:
        for field in cls.jvm_fields.values():
            if field.name == name and field.is_static == is_static:
                if not signature or field.signature == signature:
                    return field

        if cls.jvm_super is not None:
            return cls.jvm_super.find_field(name, signature, is_static)

        return None

    def find_field_by_id(cls, jvm_id: int) -> Optional['JavaFieldDef']:
        if jvm_id in cls.jvm_fields:
            return cls.jvm_fields[jvm_id]

        if cls.jvm_super is not None:
            return cls.jvm_super.find_field_by_id(jvm_id)

        return None