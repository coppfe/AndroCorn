from __future__ import annotations

from typing import TYPE_CHECKING, Optional
from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.classes.java.lang.object import Object
from androidemu.java.classes.java.lang.string import String

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator


class Throwable(Object, metaclass=JavaClassDef, jvm_name='java/lang/Throwable', jvm_super=Object):
    def __init__(self, message: str = "") -> None:
        super().__init__()
        self.detail_message: str = message

    @java_method_def(name='<init>', signature='()V', native=False)
    def ctor_void(self, emu: Emulator) -> None:
        self.detail_message = ""

    @java_method_def(name='<init>', args_list=["jstring"], signature='(Ljava/lang/String;)V', native=False)
    def ctor_msg(self, emu: Emulator, msg: String) -> None:
        self.detail_message = msg.get_py_string() if msg else ""

    @java_method_def(name='getMessage', signature='()Ljava/lang/String;', native=False)
    def getMessage(self, emu: Emulator) -> String:
        return String(self.detail_message)

    @java_method_def(name='toString', signature='()Ljava/lang/String;', native=False)
    def toString(self, emu: Emulator) -> String:
        cls_name = getattr(self.__class__, 'jvm_name', 'java/lang/Throwable').replace('/', '.')
        if self.detail_message:
            return String(f"{cls_name}: {self.detail_message}")
        return String(cls_name)


class Exception_(Throwable, metaclass=JavaClassDef, jvm_name='java/lang/Exception', jvm_super=Throwable):
    def __init__(self, message: str = "") -> None:
        super().__init__(message=message)


class ClassNotFoundException(Exception_, metaclass=JavaClassDef, jvm_name='java/lang/ClassNotFoundException', jvm_super=Exception_):
    def __init__(self, message: str = "") -> None:
        super().__init__(message=message)


class NoSuchFieldException(Exception_, metaclass=JavaClassDef, jvm_name='java/lang/NoSuchFieldException', jvm_super=Exception_):
    def __init__(self, message: str = "") -> None:
        super().__init__(message=message)


class NoSuchMethodException(Exception_, metaclass=JavaClassDef, jvm_name='java/lang/NoSuchMethodException', jvm_super=Exception_):
    def __init__(self, message: str = "") -> None:
        super().__init__(message=message)