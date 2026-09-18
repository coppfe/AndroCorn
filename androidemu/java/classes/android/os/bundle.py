from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from androidemu.java.jvm.constants import *
from ...java.lang.string import String

class Bundle(metaclass=JavaClassDef, jvm_name='android/os/Bundle'):
    
    def __init__(self, py_map = {}):
        self.__pymap = py_map
    #

    @java_method_def(name='getString', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getString(self, emu, k: 'String'):
        pykey = k.get_py_string()
        if (pykey in self.__pymap):
            return String(self.__pymap[pykey])
        else:
            #attention do not return None, return None means no return value in function, return JAVA_NULL means the return value is NULL
            return JAVA_NULL
        #
    #


    @java_method_def(name='getBoolean', args_list=["jstring"], signature='(Ljava/lang/String;)Z',
                     native=False)
    def getBoolean(self, emu, k: 'String'):
        pykey = k.get_py_string()
        if (pykey in self.__pymap):
            return bool(self.__pymap[pykey])
        else:
            # attention do not return None, return None means no return value in function, return JAVA_NULL means the return value is NULL
            return JAVA_NULL
        #
    #
#