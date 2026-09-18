from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
import logging

from ..string import String

class AccessibleObject(metaclass=JavaClassDef, jvm_name='java/lang/reflect/AccessibleObject'):
    
    def __init__(self):
        pass
    #

    @java_method_def(name='setAccessible', args_list=["jboolean"], signature='(Z)V', native=False)
    def setAccessible(self, emu, access):        
        logging.debug("AccessibleObject setAccessible call skip")
    #
#

class Field(AccessibleObject, metaclass=JavaClassDef, jvm_name='java/lang/reflect/Field', jvm_super=AccessibleObject):
    
    def __init__(self, pydeclaringClass: JavaClassDef, fieldName : str):
        super().__init__()
        self.__fieldName = fieldName
        self.declaringClass = pydeclaringClass
    #


    @java_method_def(name='get', args_list=["jobject"], signature='(Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, obj):
        logging.debug("Field.get(%r)"%obj)

        v = getattr(obj, self.__fieldName)
        return v

    @java_method_def(name='getDeclaringClass', signature='()Ljava/lang/Class;', native=False)
    def getDeclaringClass(self, emu):
        return getattr(self.declaringClass, 'class_object', self.declaringClass)

    @java_method_def(name='getName', signature='()Ljava/lang/String;', native=False)
    def getName(self, emu):
        return String(self.__fieldName)

    @java_method_def(name='getModifiers', signature='()I', native=False)
    def getModifiers(self, emu):
        return 1

    @java_method_def(name='getType', signature='()Ljava/lang/Class;', native=False)
    def getType(self, emu):
        obj_cls = emu.java_classloader.find_class_by_name('java/lang/Object')
        return getattr(obj_cls, 'class_object', None)
#
