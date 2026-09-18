from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.jvm.constants import *
from .string import *
from .reflect.method import *
from .reflect.field import *
from .array import ObjectArray

import io

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.core import Emulator
    from androidemu.java.classloader import JavaClassLoader

class Class(metaclass=JavaClassDef, jvm_name='java/lang/Class'):
    _basic_types = ["Z", "B", "C", "D", "F", "I", "J", "S"]
    def __init__(self, pyclazz, class_loader):
        self.class_loader: 'JavaClassLoader' = class_loader
        self.__pyclazz = pyclazz
        self.__descriptor_represent = pyclazz.jvm_name
    #

    @java_method_def(name='getClassLoader', signature='()Ljava/lang/ClassLoader;', native=False)
    def getClassLoader(self, emu):
        return self.class_loader
    #

    @java_method_def(
        name='getDeclaredMethods',
        signature='()[Ljava/lang/reflect/Method;',
        native=False
    )
    def getDeclaredMethods(self, emu):
        methods = []
        if self.__pyclazz and hasattr(self.__pyclazz, 'jvm_methods'):
            for jvm_id, pymethod in self.__pyclazz.jvm_methods.items():
                if pymethod.name in ("<init>", "<clinit>"):
                    continue
                methods.append(Method(self.__pyclazz, pymethod))
        return ObjectArray(methods)

    @java_method_def(
        name='getDeclaredFields',
        signature='()[Ljava/lang/reflect/Field;',
        native=False
    )
    def getDeclaredFields(self, emu):
        fields = []
        if self.__pyclazz and hasattr(self.__pyclazz, 'jvm_fields'):
            for jvm_id, pyfield in self.__pyclazz.jvm_fields.items():
                fields.append(Field(self.__pyclazz, pyfield.name))
        return ObjectArray(fields)

    @java_method_def(
        name='getFields',
        signature='()[Ljava/lang/reflect/Field;',
        native=False
    )
    def getFields(self, emu):
        return self.getDeclaredFields(emu)

    @staticmethod
    @java_method_def(name='forName', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/Class;',
                     native=False)
    def forName(emu: 'Emulator', name: 'String'):
        clz_name: str = name.get_py_string().replace(".", "/")
        clz_obj = emu.java_classloader.find_class_by_name(clz_name)
        logging.info("forName for %s", clz_name)
        return Class(clz_obj, emu.java_classloader)

    #

    # FIXME -
    @java_method_def(name='getMethod', args_list=["jstring", "jobject"]
        , signature='(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;'
        , native=False)
    def getMethod(self, emu, name, parameterTypes):
        return self.getDeclaredMethod(emu, name, parameterTypes)

    #

    @java_method_def(name='getName', signature='()Ljava/lang/String;', native=False)
    def getName(self, emu) -> 'String':
        name = self.__descriptor_represent
        assert name != None

        name = name.replace("/", ".")
        return String(name)
    #

    @java_method_def(name='getCanonicalName', signature='()Ljava/lang/String;', native=False)
    def getCanonicalName(self, emu) -> 'String':
        name = self.getName(emu).get_py_string()
        
        if (name[0] == "["):
            dims = 0
            for ch in name:
                if (ch == '['):
                    dims += 1
                #
                else:
                    break
                #
            #
            #去除[
            name = name[dims:]
            if (name[0] == "L"):
                #去除类型前的L
                name = name[1:]
            #

            for i in range(dims):
                name = name + "[]"
            #
        #
        #$->.
        name = name.replace("$", ".")
        return String(name)
    #

    def get_jni_descriptor(self) -> str:
        return self.__descriptor_represent
    #

    def get_py_clazz(self) -> 'JavaClassDef':
        return self.__pyclazz
    #


    @java_method_def(name='getDeclaredField', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/reflect/Field;', native=False)
    def getDeclaredField(self, emu, name):
        reflected_field = Field(self.__pyclazz, name.get_py_string())
        return reflected_field
    #

    @java_method_def(name='getDeclaredMethod', args_list=["jstring", "jobject"], signature='(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;', native=False)
    def getDeclaredMethod(self, emu, name, parameterTypes):
        sbuf = io.StringIO()
        sbuf.write("(")
        for item in parameterTypes:
            desc = item.get_jni_descriptor()
            if (desc[0] == "[" or desc in Class._basic_types):
                sbuf.write(desc)
            #
            else:
                sbuf.write("L")
                sbuf.write(desc)
                sbuf.write(";")
            #
        #
        sbuf.write(")")

        signature_no_ret = sbuf.getvalue()
        pyname = name.get_py_string()
        pymethod = self.__pyclazz.find_method_sig_with_no_ret(pyname, signature_no_ret)
        if (pymethod == None):
            assert False, "getDeclaredMethod not found..."
            return JAVA_NULL
        #
        reflected_method = Method(self.__pyclazz, pymethod)
        return reflected_method
    #

    def __repr__(self):
        return "Class(%s)"%self.__descriptor_represent
    #
#
