from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from ..lang.string import String

class File(metaclass=JavaClassDef, jvm_name='java/io/File'):
    
    def __init__(self, path):
        assert type(path) == str
        self.pyobject = path
    #

    @java_method_def(name='getPath', signature='()Ljava/lang/String;', native=False)
    def getPath(self, emu):
        return String(self.pyobject)
    #


    @java_method_def(name='getAbsolutePath', signature='()Ljava/lang/String;', native=False)
    def getAbsolutePath(self, emu):
        #FIXME return abspath...
        return String(self.pyobject)
    #
#
