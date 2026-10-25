from typing import TYPE_CHECKING, Dict, Optional, Any
from .class_def import JavaClassDef
from .classes.java.lang.clazz import Class
from .method_def import java_method_def

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator
    from androidemu.java.classes.java.lang.string import String


class JavaClassLoader(metaclass=JavaClassDef, jvm_name='java/lang/ClassLoader'):
    def __init__(self) -> None:
        self.class_by_id: Dict[int, JavaClassDef] = {}
        self.class_by_name: Dict[str, JavaClassDef] = {}
        self.methods_by_id: Dict[int, Any] = {}

    @staticmethod
    @java_method_def(
        name='getSystemClassLoader',
        signature='()Ljava/lang/ClassLoader;',
        native=False
    )
    def getSystemClassLoader(emu: 'Emulator') -> 'JavaClassLoader':
        return emu.java_classloader

    @java_method_def(
        name='loadClass',
        args_list=['jstring'],
        signature='(Ljava/lang/String;)Ljava/lang/Class;',
        native=False
    )
    def loadClass(self, emu: 'Emulator', class_name: 'String') -> Optional[Class]:
        if not class_name:
            return None
        py_name = class_name.get_py_string().replace('.', '/')
        clz = self.find_class_by_name(py_name)
        if clz is None:
            try:
                from .classes.java.lang.clazz import Class as ClassObj
                return ClassObj.forName(emu, class_name)
            except Exception:
                return None
        return getattr(clz, 'class_object', None)

    @java_method_def(
        name='findClass',
        args_list=['jstring'],
        signature='(Ljava/lang/String;)Ljava/lang/Class;',
        native=False
    )
    def findClass(self, emu: 'Emulator', class_name: 'String') -> Optional[Class]:
        return self.loadClass(emu, class_name)

    @java_method_def(
        name='getParent',
        signature='()Ljava/lang/ClassLoader;',
        native=False
    )
    def getParent(self, emu: 'Emulator') -> Optional['JavaClassLoader']:
        return emu.java_classloader

    def add_class(self, clazz: JavaClassDef) -> None:
        if not isinstance(clazz, JavaClassDef):
            raise ValueError('Expected a JavaClassDef.')

        if clazz.jvm_name in self.class_by_name:
            return

        if clazz.class_object is None:
            clazz.class_object = Class(clazz, self)

        self.class_by_id[clazz.jvm_id] = clazz
        self.class_by_name[clazz.jvm_name] = clazz

        for mid, mdef in clazz.jvm_methods.items():
            self.methods_by_id[mid] = (clazz, mdef)

    def find_class_by_id(self, jvm_id: int) -> Optional[JavaClassDef]:
        return self.class_by_id.get(jvm_id, None)

    def find_class_by_name(self, name: str) -> Optional[JavaClassDef]:
        norm_name = name.replace('.', '/')
        return self.class_by_name.get(norm_name, None)

    def resolve_method_globally(self, method_id: int) -> Optional[Any]:
        return self.methods_by_id.get(method_id, None)