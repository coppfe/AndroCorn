from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.jvm.constants import JAVA_NULL
from ..lang.string import String


class Objects(metaclass=JavaClassDef, jvm_name='java/util/Objects'):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name='hash',
        args_list=['jobject'],
        signature='([Ljava/lang/Object;)I',
        native=False
    )
    def hash(emu, values):
        if not values or values == JAVA_NULL:
            return 0
        
        res = 1
        items = values.get_py_items() if hasattr(values, 'get_py_items') else values
        for item in items:
            h = (id(item) & 0x7FFFFFFF) if item not in (None, JAVA_NULL) else 0
            res = (31 * res + h) & 0xFFFFFFFF
            
        return res if res < 0x80000000 else res - 0x100000000

    @staticmethod
    @java_method_def(
        name='equals',
        args_list=['jobject', 'jobject'],
        signature='(Ljava/lang/Object;Ljava/lang/Object;)Z',
        native=False
    )
    def equals(emu, a, b):
        if a is b:
            return True
        if a == JAVA_NULL or b == JAVA_NULL or a is None or b is None:
            return False
        return a == b

    @staticmethod
    @java_method_def(
        name='deepEquals',
        args_list=['jobject', 'jobject'],
        signature='(Ljava/lang/Object;Ljava/lang/Object;)Z',
        native=False
    )
    def deepEquals(emu, a, b):
        return Objects.equals(emu, a, b)

    @staticmethod
    @java_method_def(
        name='hashCode',
        args_list=['jobject'],
        signature='(Ljava/lang/Object;)I',
        native=False
    )
    def hashCode(emu, o):
        if o == JAVA_NULL or o is None:
            return 0
        return id(o) & 0x7FFFFFFF

    @staticmethod
    @java_method_def(
        name='toString',
        args_list=['jobject'],
        signature='(Ljava/lang/Object;)Ljava/lang/String;',
        native=False
    )
    def toString(emu, o):
        if o == JAVA_NULL or o is None:
            return String("null")
        return String(str(o))

    @staticmethod
    @java_method_def(
        name='toString',
        args_list=['jobject', 'jstring'],
        signature='(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;',
        native=False
    )
    def toStringDefault(emu, o, null_default):
        if o == JAVA_NULL or o is None:
            return null_default
        return String(str(o))

    @staticmethod
    @java_method_def(
        name='requireNonNull',
        args_list=['jobject'],
        signature='(Ljava/lang/Object;)Ljava/lang/Object;',
        native=False
    )
    def requireNonNull(emu, obj):
        return obj

    @staticmethod
    @java_method_def(
        name='requireNonNull',
        args_list=['jobject', 'jstring'],
        signature='(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;',
        native=False
    )
    def requireNonNullMsg(emu, obj, msg):
        return obj

    @staticmethod
    @java_method_def(
        name='isNull',
        args_list=['jobject'],
        signature='(Ljava/lang/Object;)Z',
        native=False
    )
    def isNull(emu, obj):
        return obj == JAVA_NULL or obj is None

    @staticmethod
    @java_method_def(
        name='nonNull',
        args_list=['jobject'],
        signature='(Ljava/lang/Object;)Z',
        native=False
    )
    def nonNull(emu, obj):
        return obj != JAVA_NULL and obj is not None