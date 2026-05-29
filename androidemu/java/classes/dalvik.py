from ..class_def import JavaClassDef
from ..field_def import JavaFieldDef
from ..method_def import java_method_def, JavaMethodDef

class DalvikVM(metaclass=JavaClassDef, jvm_name='dalvik/system/BaseDexClassLoader'):

    def __init__(self):
        pass
