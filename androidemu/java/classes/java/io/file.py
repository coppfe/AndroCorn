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


FD_IN  = JavaFieldDef('in',  'Ljava/io/FileDescriptor;', True, object())
FD_OUT = JavaFieldDef('out', 'Ljava/io/FileDescriptor;', True, object())
FD_ERR = JavaFieldDef('err', 'Ljava/io/FileDescriptor;', True, object())

class FileDescriptor(metaclass=JavaClassDef, jvm_name='java/io/FileDescriptor',
                     jvm_fields=[
                         JavaFieldDef('descriptor', 'I', False),
                         FD_IN,
                         FD_OUT,
                         FD_ERR,
                     ]):
    def __init__(self, fd: int = -1):
        self.descriptor = fd

    @java_method_def(name='<init>', signature='()V', native=False)
    def init_void(self, emu):
        self.descriptor = -1

    @java_method_def(name='<init>', args_list=['jint'], signature='(I)V', native=False)
    def init_int(self, emu, fd: int):
        self.descriptor = fd

    @java_method_def(name='valid', signature='()Z', native=False)
    def valid(self, emu):
        return self.descriptor != -1


FD_IN.static_value  = FileDescriptor(0)
FD_OUT.static_value = FileDescriptor(1)
FD_ERR.static_value = FileDescriptor(2)