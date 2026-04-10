from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .array import Array

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ...emulator import Emulator

class NetworkInterface(metaclass=JavaClassDef, jvm_name='java/net/NetworkInterface'):
    def __init__(self, pyname):
        self.__name = pyname
    #

    @staticmethod
    @java_method_def(name='getByName', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/net/NetworkInterface;', native=False)
    def getByName(emu, s1):
        # print("getByName %r"%s1)
        pyname = s1.get_py_string()
        return NetworkInterface(pyname)
    #

    @java_method_def(name='getHardwareAddress', signature='()[B', native=False)
    def getHardwareAddress(self, emu: "Emulator"):
        mac = emu.config.pkg.device.net.mac
        barr = bytearray(mac)
        arr = Array(barr)
        return arr
    #
#