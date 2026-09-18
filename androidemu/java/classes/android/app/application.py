from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from ..content.context import ContextImpl, Context, ContextWrapper


class Application(ContextWrapper, metaclass=JavaClassDef, jvm_name='android/app/Application', jvm_super=ContextWrapper):

    def __init__(self):
        pass
    #
    
#