import logging

from .executable import Executable
from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from androidemu.java.jvm.constants import *
from ..string import String
from ..array import ObjectArray

logger = logging.getLogger(__name__)

class Method(metaclass=JavaClassDef,
             jvm_name='java/lang/reflect/Method',
             jvm_fields=[
                 JavaFieldDef('slot', 'I', False, ignore=True),
                 JavaFieldDef('declaringClass', 'Ljava/lang/Class;', False),
             ],
             jvm_super=Executable):

    def __init__(self, pydeclaringClass: JavaClassDef, pymethod: JavaMethodDef):
        super().__init__()
        self._method = pymethod
        self.slot = pymethod.jvm_id
        self.declaringClass = getattr(pydeclaringClass, 'class_object', pydeclaringClass)
        self.accessFlags = pymethod.modifier if pymethod.modifier is not None else 1
    #

    @java_method_def(name='getDeclaringClass', signature='()Ljava/lang/Class;', native=False)
    def getDeclaringClass(self, emu):
        return self.declaringClass

    @java_method_def(name='getName', signature='()Ljava/lang/String;', native=False)
    def getName(self, emu):
        return String(self._method.name)

    @java_method_def(name='getModifiers', signature='()I', native=False)
    def getModifiers(self, emu):
        return self.accessFlags

    @java_method_def(name='getParameterTypes', signature='()[Ljava/lang/Class;', native=False)
    def getParameterTypes(self, emu):
        return ObjectArray([])

    @java_method_def(name='getReturnType', signature='()Ljava/lang/Class;', native=False)
    def getReturnType(self, emu):
        # from ..clazz import Class
        obj_cls = emu.java_classloader.find_class_by_name('java/lang/Object')
        return getattr(obj_cls, 'class_object', None)

    @staticmethod
    @java_method_def(
        name="getMethodModifiers",
        signature="(Ljava/lang/Class;I)I",
        args_list=['jobject', 'jint']
    )
    def getMethodModifiers(emu, clazz_obj, jvm_method_id):
        clazz = clazz_obj.value
        method = clazz.find_method_by_id(jvm_method_id)
        if method.modifier is None:
            raise RuntimeError('No modifier was given to class %s method %s' % (clazz.jvm_name, method.name))

        return method.modifier
    #

    @java_method_def(
        name="invoke",
        signature="(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
        args_list=['jobject', 'jobject']
    )
    def invoke(self, emu, obj, args):
        if(obj == JAVA_NULL):
            #static method
            v = self._method.func(emu, *args)
        #
        else:
            v = self._method.func(obj, emu, *args)
        #
        return v

    #

    @java_method_def(
        name="setAccessible",
        signature="(Z)V",
        args_list=['jboolean']
    )
    def setAccessible(self, emu, flag):
        pass
    #

    def __repr__(self):
        return "Method(%s, %s)"%(self.declaringClass, self._method)