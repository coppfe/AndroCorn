from ..class_def import JavaClassDef
from ..field_def import JavaFieldDef
from ..method_def import java_method_def, JavaMethodDef
from .context import ContextImpl, Context, ContextWrapper


class Application(ContextWrapper, metaclass=JavaClassDef, jvm_name='android/app/Application', jvm_super=ContextWrapper):

    def __init__(self):
        pass
    #
    
#