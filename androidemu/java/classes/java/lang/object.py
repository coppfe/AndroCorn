from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from .string import String


class Object(metaclass=JavaClassDef, jvm_name='java/lang/Object'):
    
    def __init__(self):
        pass

    @java_method_def(name='toString', signature='()Ljava/lang/String;', native=False)
    def toString(self, emu):
        cls_name = getattr(self.__class__, 'jvm_name', 'java/lang/Object').replace('/', '.')
        return String(f"{cls_name}@{hex(id(self))}")

    @java_method_def(name='hashCode', signature='()I', native=False)
    def hashCode(self, emu):
        return id(self) & 0x7FFFFFFF

    @java_method_def(name='equals', args_list=['jobject'], signature='(Ljava/lang/Object;)Z', native=False)
    def equals(self, emu, other):
        return self is other

    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object