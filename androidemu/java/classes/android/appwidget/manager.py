from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def

class AppWidgetManager(metaclass=JavaClassDef, jvm_name="android/appwidget/AppWidgetManager"):
    
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getInstance", 
        args_list=["jobject"], 
        signature="(Landroid/content/Context;)Landroid/appwidget/AppWidgetManager;", 
        native=False
    )
    def getInstance(emu, context):
        return AppWidgetManager()

    @java_method_def(
        name="getAppWidgetIds",
        args_list=["jobject"],
        signature="(Landroid/content/ComponentName;)[I",
        native=False
    )
    def getAppWidgetIds(self, emu, component_name):
        from ...java.lang.array import IntArray
        return IntArray([1])