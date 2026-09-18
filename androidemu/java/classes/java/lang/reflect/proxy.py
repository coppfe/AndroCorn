from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef

class Proxy(metaclass=JavaClassDef, jvm_name='java/lang/reflect/Proxy'):
    
    def __init__(self):
        pass
    #

#