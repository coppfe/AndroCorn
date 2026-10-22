from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def
from .clazz import Class

# Every box class has a static field TYPE: the Class object of the primitive it boxes (Integer.TYPE is int.class)
def _type_field(descriptor: str) -> JavaFieldDef:
    return JavaFieldDef('TYPE', 'Ljava/lang/Class;', True, Class.primitive(descriptor))

class Boolean(metaclass=JavaClassDef, jvm_name='java/lang/Boolean', jvm_fields=[_type_field('Z')]):
    
    def __init__(self, value=False):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jboolean"], signature='(Z)V', native=False)
    def ctor(self, emu, value):
        self.pyobject = value
    #

    @java_method_def(name='valueOf', args_list=["jboolean"], signature='(Z)Ljava/lang/Boolean;', native=False)
    def valueOf(emu, value):
        return Boolean(value)
    
    #

    @java_method_def(name='booleanValue', signature='()Z', native=False)
    def booleanValue(self, emu):
        return self.pyobject
    #

    def __repr__(self):
        return "%r"%self.pyobject
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#


class Integer(metaclass=JavaClassDef, jvm_name='java/lang/Integer', jvm_fields=[_type_field('I')]):
    _INTEGER_CACHE = {}
    
    def __init__(self, value=0):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jint"], signature='(I)V', native=False)
    def ctor(self, emu, value):
        self.pyobject = value
    #

    @java_method_def(name='intValue', signature='()I', native=False)
    def intValue(self, emu):
        return self.pyobject
    #

    def __repr__(self):
        return "%r"%self.pyobject
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    
    @staticmethod
    @java_method_def(
        name='valueOf',
        args_list=['jint'],
        signature='(I)Ljava/lang/Integer;',
        native=False
    )
    def valueOf(emu, value):
        if -128 <= value <= 127:
            if value not in Integer._INTEGER_CACHE:
                Integer._INTEGER_CACHE[value] = Integer(value)
            return Integer._INTEGER_CACHE[value]

        return Integer(value)

class Long(metaclass=JavaClassDef, jvm_name='java/lang/Long', jvm_fields=[_type_field('J')]):
    
    def __init__(self, value=0):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jlong"], signature='(J)V', native=False)
    def ctor(self, emu, lvalue):

        self.pyobject = lvalue
    #

    @java_method_def(name='longValue', signature='()J', native=False)
    def longValue(self, emu):
        return self.pyobject
    #

    @java_method_def(name='valueOf', args_list=["jlong"], signature='(J)Ljava/lang/Long;', native=False)
    def valueOf(emu, lvalue):
        return Long(lvalue)

    def __repr__(self):
        return "%r"%self.pyobject
    #    
    
    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #

    def get_py_value(self):
        return self.pyobject
    #
#



class Float(metaclass=JavaClassDef, jvm_name='java/lang/Float', jvm_fields=[_type_field('F')]):
    
    def __init__(self, value=0.0):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jfloat"], signature='(F)V', native=False)
    def ctor(self, emu, value):
        self.pyobject = value
    #

    @staticmethod
    @java_method_def(name='valueOf', args_list=["jfloat"], signature='(F)Ljava/lang/Float;', native=False)
    def valueOf(emu, value):
        return Float(value)
    #

    @java_method_def(name='floatValue', signature='()F', native=False)
    def floatValue(self, emu):
        return self.pyobject
    #

    def __repr__(self):
        return "%r"%self.pyobject
    #
    
    # #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#


class Short(metaclass=JavaClassDef, jvm_name='java/lang/Short', jvm_fields=[_type_field('S')]):

    def __init__(self, value=0):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jshort"], signature='(S)V', native=False)
    def ctor(self, emu, value):
        self.pyobject = value
    #

    @staticmethod
    @java_method_def(name='valueOf', args_list=["jshort"], signature='(S)Ljava/lang/Short;', native=False)
    def valueOf(emu, value):
        return Short(value)
    #

    @java_method_def(name='shortValue', signature='()S', native=False)
    def shortValue(self, emu):
        return self.pyobject
    #

    def __repr__(self):
        return "%r"%self.pyobject
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#


class Byte(metaclass=JavaClassDef, jvm_name='java/lang/Byte', jvm_fields=[_type_field('B')]):

    def __init__(self, value=0):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jbyte"], signature='(B)V', native=False)
    def ctor(self, emu, value):
        self.pyobject = value
    #

    @staticmethod
    @java_method_def(name='valueOf', args_list=["jbyte"], signature='(B)Ljava/lang/Byte;', native=False)
    def valueOf(emu, value):
        return Byte(value)
    #

    @java_method_def(name='byteValue', signature='()B', native=False)
    def byteValue(self, emu):
        return self.pyobject
    #

    def __repr__(self):
        return "%r"%self.pyobject
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#


class Character(metaclass=JavaClassDef, jvm_name='java/lang/Character', jvm_fields=[_type_field('C')]):

    def __init__(self, value=0):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jchar"], signature='(C)V', native=False)
    def ctor(self, emu, value):
        self.pyobject = value
    #

    @staticmethod
    @java_method_def(name='valueOf', args_list=["jchar"], signature='(C)Ljava/lang/Character;', native=False)
    def valueOf(emu, value):
        return Character(value)
    #

    @java_method_def(name='charValue', signature='()C', native=False)
    def charValue(self, emu):
        return self.pyobject
    #

    def __repr__(self):
        return "%r"%self.pyobject
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#


class Double(metaclass=JavaClassDef, jvm_name='java/lang/Double', jvm_fields=[_type_field('D')]):

    def __init__(self, value=0.0):
        self.pyobject = value
    #

    @java_method_def(name='<init>', args_list=["jdouble"], signature='(D)V', native=False)
    def ctor(self, emu, value):
        self.pyobject = value
    #

    @staticmethod
    @java_method_def(name='valueOf', args_list=["jdouble"], signature='(D)Ljava/lang/Double;', native=False)
    def valueOf(emu, value):
        return Double(value)
    #

    @java_method_def(name='doubleValue', signature='()D', native=False)
    def doubleValue(self, emu):
        return self.pyobject
    #

    def __repr__(self):
        return "%r"%self.pyobject
    #

    #TODO: 在继承多态机制完善后移动到Object类上
    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
    #
#
