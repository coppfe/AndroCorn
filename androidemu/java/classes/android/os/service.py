from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from .binder import BinderProxy

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...java.lang.string import String

class ServiceManager(metaclass=JavaClassDef, jvm_name='android/os/ServiceManager'):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name='getService',
        args_list=['jstring'],
        signature='(Ljava/lang/String;)Landroid/os/IBinder;',
        native=False
    )
    def getService(emu, service_name: 'String'):
        name = service_name.get_py_string() if service_name else ""
        return BinderProxy(service_name=name)

    @staticmethod
    @java_method_def(
        name='checkService',
        args_list=['jstring'],
        signature='(Ljava/lang/String;)Landroid/os/IBinder;',
        native=False
    )
    def checkService(emu, service_name: 'String'):
        name = service_name.get_py_string() if service_name else ""
        return BinderProxy(service_name=name)