from ..class_def import JavaClassDef
from ..field_def import JavaFieldDef
from ..method_def import java_method_def, JavaMethodDef

class Object(metaclass=JavaClassDef, jvm_name='java/lang/Object'):
    
    def __init__(self):
        pass
    #

#