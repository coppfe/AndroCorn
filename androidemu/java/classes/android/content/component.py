from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def

class ComponentName(metaclass=JavaClassDef, jvm_name="android/content/ComponentName"):
    
    def __init__(self, pkg: str = "", cls: str = ""):
        self.pkg = pkg
        self.cls = cls

    @java_method_def(
        name="<init>", 
        args_list=["jstring", "jstring"], 
        signature="(Ljava/lang/String;Ljava/lang/String;)V", 
        native=False
    )
    def init_str_str(self, emu, pkg, cls):
        self.pkg = pkg.get_py_string() if pkg else ""
        self.cls = cls.get_py_string() if cls else ""

    @java_method_def(
        name="<init>", 
        args_list=["jobject", "jstring"], 
        signature="(Landroid/content/Context;Ljava/lang/String;)V", 
        native=False
    )
    def init_ctx_str(self, emu, context, cls):
        self.pkg = context.getPackageName(emu).get_py_string() if context else ""
        self.cls = cls.get_py_string() if cls else ""

    @java_method_def(
        name="<init>", 
        args_list=["jobject", "jobject"], 
        signature="(Landroid/content/Context;Ljava/lang/Class;)V", 
        native=False
    )
    def init_ctx_class(self, emu, context, clazz):
        self.pkg = context.getPackageName(emu).get_py_string() if context else ""
        self.cls = clazz.getName(emu).get_py_string() if clazz else ""