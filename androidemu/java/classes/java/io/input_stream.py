from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.jvm.constants import JAVA_NULL
from ..lang.array import ByteArray

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

logger = logging.getLogger("androidemu.java.io")


class InputStream(metaclass=JavaClassDef, jvm_name='java/io/InputStream'):

    def __init__(self) -> None:
        pass

    @java_method_def(name='read', signature='()I', native=False)
    def read_one(self, emu: Emulator) -> int:
        return -1

    @java_method_def(name='read', args_list=["jobject"], signature='([B)I', native=False)
    def read_buf(self, emu: Emulator, b: ByteArray) -> int:
        return -1

    @java_method_def(name='read', args_list=["jobject", "jint", "jint"], signature='([BII)I', native=False)
    def read_buf_range(self, emu: Emulator, b: ByteArray, off: int, length: int) -> int:
        return -1

    @java_method_def(name='close', signature='()V', native=False)
    def close(self, emu: Emulator) -> None:
        pass

    @java_method_def(name='available', signature='()I', native=False)
    def available(self, emu: Emulator) -> int:
        return 0


class ByteArrayInputStream(InputStream, metaclass=JavaClassDef, jvm_name='java/io/ByteArrayInputStream', jvm_super=InputStream):

    def __init__(self, data: Optional[bytes | bytearray | ByteArray] = None) -> None:
        super().__init__()
        if data is None:
            self._buf = bytearray()
        elif isinstance(data, (bytes, bytearray)):
            self._buf = bytearray(data)
        elif isinstance(data, ByteArray):
            self._buf = bytearray(data.get_py_items())
        else:
            self._buf = bytearray()

        self._pos: int = 0
        self._count: int = len(self._buf)
        self._mark: int = 0

    # <init>([B)V
    @java_method_def(
        name='<init>',
        args_list=["jobject"],
        signature='([B)V',
        native=False
    )
    def ctor_buf(self, emu: Emulator, barr: ByteArray) -> None:
        if barr and barr != JAVA_NULL:
            items = barr.get_py_items()
            self._buf = bytearray(items)
        else:
            self._buf = bytearray()
        self._pos = 0
        self._count = len(self._buf)
        self._mark = 0

    # <init>([BII)V
    @java_method_def(
        name='<init>',
        args_list=["jobject", "jint", "jint"],
        signature='([BII)V',
        native=False
    )
    def ctor_buf_offset(self, emu: Emulator, barr: ByteArray, offset: int, length: int) -> None:
        if barr and barr != JAVA_NULL:
            items = barr.get_py_items()
            raw = bytes(items)
            self._buf