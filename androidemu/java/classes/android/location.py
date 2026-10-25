import time
from typing import TYPE_CHECKING

from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.classes.java.lang.object import Object
from androidemu.java.classes.java.lang.string import String

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator


class Location(Object, metaclass=JavaClassDef, jvm_name='android/location/Location', jvm_super=Object):

    def __init__(self, provider: str = "gps") -> None:
        super().__init__()
        self.provider: str = provider
        self.latitude: float = 41.0082
        self.longitude: float = 28.9784
        self.altitude: float = 30.0
        self.accuracy: float = 5.0
        self.speed: float = 0.0
        self.bearing: float = 0.0
        self.time_ms: int = int(time.time() * 1000)
        self.is_mock: bool = False

    @java_method_def(name='<init>', signature='()V', native=False)
    def ctor_void(self, emu: 'Emulator') -> None:
        pass

    @java_method_def(name='<init>', args_list=["jstring"], signature='(Ljava/lang/String;)V', native=False)
    def ctor_provider(self, emu: 'Emulator', provider: String) -> None:
        self.provider = provider.get_py_string() if provider else "gps"

    @java_method_def(name='setLatitude', args_list=["jdouble"], signature='(D)V', native=False)
    def setLatitude(self, emu: 'Emulator', lat: float) -> None:
        self.latitude = float(lat)

    @java_method_def(name='setLongitude', args_list=["jdouble"], signature='(D)V', native=False)
    def setLongitude(self, emu: 'Emulator', lon: float) -> None:
        self.longitude = float(lon)

    @java_method_def(name='setAltitude', args_list=["jdouble"], signature='(D)V', native=False)
    def setAltitude(self, emu: 'Emulator', alt: float) -> None:
        self.altitude = float(alt)

    @java_method_def(name='setAccuracy', args_list=["jfloat"], signature='(F)V', native=False)
    def setAccuracy(self, emu: 'Emulator', acc: float) -> None:
        self.accuracy = float(acc)

    @java_method_def(name='setTime', args_list=["jlong"], signature='(J)V', native=False)
    def setTime(self, emu: 'Emulator', t: int) -> None:
        self.time_ms = int(t)

    @java_method_def(name='setElapsedRealtimeNanos', args_list=["jlong"], signature='(J)V', native=False)
    def setElapsedRealtimeNanos(self, emu: 'Emulator', nanos: int) -> None:
        pass

    @java_method_def(name='setSpeed', args_list=["jfloat"], signature='(F)V', native=False)
    def setSpeed(self, emu: 'Emulator', speed: float) -> None:
        self.speed = float(speed)

    @java_method_def(name='setBearing', args_list=["jfloat"], signature='(F)V', native=False)
    def setBearing(self, emu: 'Emulator', bearing: float) -> None:
        self.bearing = float(bearing)

    @java_method_def(name='setProvider', args_list=["jstring"], signature='(Ljava/lang/String;)V', native=False)
    def setProvider(self, emu: 'Emulator', provider: String) -> None:
        self.provider = provider.get_py_string() if provider else "gps"

    @java_method_def(name='reset', signature='()V', native=False)
    def reset(self, emu: 'Emulator') -> None:
        self.latitude = 0.0
        self.longitude = 0.0
        self.altitude = 0.0
        self.accuracy = 0.0

    @java_method_def(name='getLatitude', signature='()D', native=False)
    def getLatitude(self, emu: 'Emulator') -> float:
        return self.latitude

    @java_method_def(name='getLongitude', signature='()D', native=False)
    def getLongitude(self, emu: 'Emulator') -> float:
        return self.longitude

    @java_method_def(name='getAltitude', signature='()D', native=False)
    def getAltitude(self, emu: 'Emulator') -> float:
        return self.altitude

    @java_method_def(name='getAccuracy', signature='()F', native=False)
    def getAccuracy(self, emu: 'Emulator') -> float:
        return self.accuracy

    @java_method_def(name='getSpeed', signature='()F', native=False)
    def getSpeed(self, emu: 'Emulator') -> float:
        return self.speed

    @java_method_def(name='getBearing', signature='()F', native=False)
    def getBearing(self, emu: 'Emulator') -> float:
        return self.bearing

    @java_method_def(name='getTime', signature='()J', native=False)
    def getTime(self, emu: 'Emulator') -> int:
        return self.time_ms

    @java_method_def(name='getElapsedRealtimeNanos', signature='()J', native=False)
    def getElapsedRealtimeNanos(self, emu: 'Emulator') -> int:
        return int(emu.time_manager.get_current_time_us() * 1000)

    @java_method_def(name='isFromMockProvider', signature='()Z', native=False)
    def isFromMockProvider(self, emu: 'Emulator') -> bool:
        return False

    @java_method_def(name='getProvider', signature='()Ljava/lang/String;', native=False)
    def getProvider(self, emu: 'Emulator') -> String:
        return String(self.provider)

    @java_method_def(name='hasAccuracy', signature='()Z', native=False)
    def hasAccuracy(self, emu: 'Emulator') -> bool:
        return True

    @java_method_def(name='hasAltitude', signature='()Z', native=False)
    def hasAltitude(self, emu: 'Emulator') -> bool:
        return True

    @java_method_def(name='hasSpeed', signature='()Z', native=False)
    def hasSpeed(self, emu: 'Emulator') -> bool:
        return True

    @java_method_def(name='hasBearing', signature='()Z', native=False)
    def hasBearing(self, emu: 'Emulator') -> bool:
        return True


class LocationManager(Object, metaclass=JavaClassDef, jvm_name='android/location/LocationManager', jvm_super=Object):
    def __init__(self) -> None:
        super().__init__()
        self._last_location = Location("gps")

    @java_method_def(
        name='getLastKnownLocation',
        args_list=["jstring"],
        signature='(Ljava/lang/String;)Landroid/location/Location;',
        native=False
    )
    def getLastKnownLocation(self, emu: 'Emulator', provider: String) -> Location:
        return self._last_location

    @java_method_def(
        name='isProviderEnabled',
        args_list=["jstring"],
        signature='(Ljava/lang/String;)Z',
        native=False
    )
    def isProviderEnabled(self, emu: 'Emulator', provider: String) -> bool:
        return True