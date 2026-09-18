from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def,JavaMethodDef
from androidemu.java.jvm.constants import *


class List(metaclass=JavaClassDef, jvm_name='java/util/List'):
    def __new__(cls, *args, **kwargs):
        obj = object.__new__(cls)
        return obj

    def __init__(self, pylist=None):
        self.pyobject = pylist if pylist is not None else []

    def __len__(self):
        return len(self.pyobject)

    def __getitem__(self, index):
        return self.pyobject[index]

    def __setitem__(self, index, value):
        self.pyobject[index] = value

    @java_method_def(name='get', args_list=["jint"], signature='(I)Ljava/lang/Object;', native=False)
    def get(self, emu, index):
        if index < len(self.pyobject):
            return self.pyobject[index]
        return JAVA_NULL

    @java_method_def(name='size', signature='()I', native=False)
    def size(self, emu):
        return len(self.pyobject)

    @java_method_def(name='isEmpty', signature='()Z', native=False)
    def isEmpty(self, emu):
        return len(self.pyobject) == 0