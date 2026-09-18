from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def,JavaMethodDef
from androidemu.java.jvm.constants import *
from ..lang.array import *


class Set(metaclass=JavaClassDef, jvm_name='java/util/Set'):
    def __init__(self, pyset):
        self.pyobject = pyset
    #

    @java_method_def(name='<init>', signature='()V', native=False)
    def ctor(self, emu):
        self.pyobject = set()
    #

    def __len__(self):
        return len(self.pyobject)
    #

    def __getitem__(self,key):
        return self.pyobject[key]
    #

    '''
    @java_method_def(name='get', args_list=["jobject"], signature='(Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, key):
        if (key in self.pyobject):
            return self.pyobject[key]
        return JAVA_NULL
    #


    @java_method_def(name='put', args_list=["jobject", "jobject"], signature='(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, key, value):
        prev = JAVA_NULL
        if (key in self.pyobject):
            prev = self.pyobject[key]
        #
        self.pyobject[key] = value
        return prev
    #
    '''

    @java_method_def(name='toArray', signature='()[Ljava/lang/Object;', native=False)
    def toArray(self, emu):
        return Array(list(self.pyobject))
    #


    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        return len(self.pyobject)
    #
#