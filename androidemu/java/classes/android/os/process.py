from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.jvm.constants import JAVA_NULL

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu import Emulator

class Process(metaclass=JavaClassDef, jvm_name='android/os/Process'):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name='myPid',
        signature='()I',
        native=False
    )
    def myPid(emu: 'Emulator'):
        return emu.config.pkg.pid

    @staticmethod
    @java_method_def(
        name='myUid',
        signature='()I',
        native=False
    )
    def myUid(emu: 'Emulator'):
        return emu.config.pkg.uid

    @staticmethod
    @java_method_def(
        name='myTid',
        signature='()I',
        native=False
    )
    def myTid(emu: 'Emulator'):
        return emu.pcb.current_tid

    @staticmethod
    @java_method_def(
        name='killProcess',
        args_list=["jint"],
        signature='(I)V',
        native=False
    )
    def killProcess(emu, pid):
        pass # da fuh?

    @staticmethod
    @java_method_def(
        name='getStartElapsedRealtime',
        signature='()J',
        native=False
    )
    def getStartElapsedRealtime(emu: 'Emulator'):
        start_ts = emu.config.pkg.start_timestamp
        return int(start_ts * 1000)