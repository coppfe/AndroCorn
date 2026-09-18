from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef

class Array(metaclass=JavaClassDef, jvm_name='java/lang/reflect/Array'):

    def __init__(self, pyitems):
        self.pyobject = pyitems
    #

    def get_py_items(self):
        return self.pyobject
    #

    def __len__(self):
        return len(self.pyobject)
    #

    def __getitem__(self,index):
        return self.pyobject[index]
    #

    def __setitem__(self,index,value):
        self.pyobject[index] = value
    #

    def __repr__(self):
        return "JavaArray(%r)"%self.get_py_items()
    #

    @staticmethod
    @java_method_def(name='set', signature='(Ljava/lang/Object;I)Ljava/lang/Object;', native=False)
    def set(emu, obj, index):
        raise NotImplementedError()
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
    
    @java_method_def(name="get", signature="(I)Ljava/lang/Object;", native=False)
    def get(self, emu, index):
        return self.pyobject[index]
    #


#

#外面用到，因为与Array jvm name不同，所以暂时手动定义，与Array作用一样
class ByteArray(Array, metaclass=JavaClassDef, jvm_name="[B", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)
    #

#

#外面用到，因为与Array jvm name不同，所以暂时手动定义，与Array作用一样
class ObjectArray(Array, metaclass=JavaClassDef, jvm_name="[Ljava/lang/Object;", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)
    #

#

class ClassArray(Array, metaclass=JavaClassDef, jvm_name="[Ljava/lang/Class;", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)
    #

#


class StringArray(Array, metaclass=JavaClassDef, jvm_name="[Ljava/lang/String;", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)
    #
#

class IntArray(Array, metaclass=JavaClassDef, jvm_name="[I", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)