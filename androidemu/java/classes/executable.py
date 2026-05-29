from ..class_def import JavaClassDef
from ..field_def import JavaFieldDef


class Executable(metaclass=JavaClassDef,
                 jvm_name='java/lang/reflect/Executable',
                 jvm_fields=[
                     JavaFieldDef('accessFlags', 'I', False)
                 ]):

    def __init__(self):
        pass
