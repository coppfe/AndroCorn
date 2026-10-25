from __future__ import annotations
from typing import TYPE_CHECKING

from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from .array import *

from androidemu.java.types import jint, jboolean, JString, JByteArray, JClass

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

class String(metaclass=JavaClassDef, jvm_name='java/lang/String'):
    def __init__(self, pystr: str = ""):
        self.pyobject: str = pystr

    def get_py_string(self) -> str:
        return self.pyobject

    @java_method_def(name='<init>', signature='([BLjava/lang/String;)V')
    def ctor(self, emu: Emulator, barr: JByteArray, charset: JString) -> None:
        pyarr = barr.get_py_items()
        pystr = charset.get_py_string()
        self.pyobject = pyarr.decode(pystr)

    @java_method_def(name='getBytes', args_list=["jstring"], signature='(Ljava/lang/String;)[B', native=False)
    def getBytes(self, emu, charset):
        pycharset = charset.get_py_string()
        barr = bytearray(self.pyobject, pycharset)
        arr = ByteArray(barr)
        return arr

    @java_method_def(name='length', signature='()I')
    def length(self, emu: Emulator) -> jint:
        return len(self.pyobject)

    @java_method_def(name='getClass', signature='()Ljava/lang/Class;', native=False)
    def getClass(self, emu):
        return self.class_object
        
    def __repr__(self):
        return "JavaString(%s)"%self.get_py_string()