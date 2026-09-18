from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from ...java.io.file import File
from ...java.lang.string import String

class Environment(metaclass=JavaClassDef, jvm_name='android/os/Environment'):
    
    def __init__(self):
        pass
    #

    @staticmethod
    @java_method_def(name='getExternalStorageDirectory', signature='()Ljava/io/File;', native=False)
    def getExternalStorageDirectory(emu):
        return File("/sdcard/")
    #
#