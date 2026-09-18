from .class_def import JavaClassDef
from .classes.java.lang.clazz import Class
from .method_def import java_method_def

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator
    from androidemu.java.classes.java.lang.string import String

class JavaClassLoader(metaclass=JavaClassDef, jvm_name='java/lang/ClassLoader'):
    def __init__(self):
        self.class_by_id = dict()
        self.class_by_name = dict()

    @java_method_def(name='loadClass', args_list=['jstring'], signature='(Ljava/lang/String;)Ljava/lang/Class;', native=False)
    def loadClass(self, emu: 'Emulator', class_name: 'String'):
        return self.find_class_by_name(class_name.get_py_string())

    def add_class(self, clazz: JavaClassDef) -> None:
        """
        Add a PyClass to the classloader

        :param clazz: PyClass
        """

        if not isinstance(clazz, JavaClassDef):
            raise ValueError('Expected a JavaClassDef.')

        if clazz.jvm_name in self.class_by_name:
            raise KeyError('The class \'%s\' is already registered.' % clazz.jvm_name)

        if (clazz.class_object == None):
            #FIXME 两个emulaotr add_class是同一个class 实例,会互相影响
            clazz.class_object = Class(clazz, self)
    
        self.class_by_id[clazz.jvm_id] = clazz
        self.class_by_name[clazz.jvm_name] = clazz

    def find_class_by_id(self, jvm_id: int) -> 'JavaClassDef':
        """
        Find a PyClass by its ID

        :param jvm_id: ID
        :return: PyClass
        """
        return self.class_by_id.get(jvm_id, None)

    def find_class_by_name(self, name: str) -> 'JavaClassDef':
        """
        Find a PyClass by its name

        :param name: Name
        :return: PyClass
        """
        return self.class_by_name.get(name, None)