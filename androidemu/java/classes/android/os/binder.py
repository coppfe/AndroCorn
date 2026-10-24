import logging
from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def
from androidemu.java.classes.java.lang.string import String

logger = logging.getLogger(__name__)

class Parcel(metaclass=JavaClassDef, jvm_name='android/os/Parcel'):
    def __init__(self):
        self._buffer = []
        self._pos = 0

    @staticmethod
    @java_method_def(name='obtain', signature='()Landroid/os/Parcel;', native=False)
    def obtain(emu):
        return Parcel()

    @java_method_def(name='recycle', signature='()V', native=False)
    def recycle(self, emu):
        self._buffer.clear()
        self._pos = 0

    @java_method_def(name='writeInt', args_list=['jint'], signature='(I)V', native=False)
    def writeInt(self, emu, val):
        self._buffer.append(val)

    @java_method_def(name='writeLong', args_list=['jlong'], signature='(J)V', native=False)
    def writeLong(self, emu, val):
        self._buffer.append(val)

    @java_method_def(name='writeFloat', args_list=['jfloat'], signature='(F)V', native=False)
    def writeFloat(self, emu, val):
        self._buffer.append(val)

    @java_method_def(name='writeDouble', args_list=['jdouble'], signature='(D)V', native=False)
    def writeDouble(self, emu, val):
        self._buffer.append(val)

    @java_method_def(name='writeString', args_list=['jstring'], signature='(Ljava/lang/String;)V', native=False)
    def writeString(self, emu, val):
        py_str = val.get_py_string() if val else ""
        self._buffer.append(py_str)

    @java_method_def(name='writeInterfaceToken', args_list=['jstring'], signature='(Ljava/lang/String;)V', native=False)
    def writeInterfaceToken(self, emu, token):
        py_token = token.get_py_string() if token else ""
        self._buffer.append(py_token)

    @java_method_def(name='writeStrongBinder', args_list=['jobject'], signature='(Landroid/os/IBinder;)V', native=False)
    def writeStrongBinder(self, emu, binder):
        self._buffer.append(binder)

    @java_method_def(name='writeFileDescriptor', args_list=['jobject'], signature='(Ljava/io/FileDescriptor;)V', native=False)
    def writeFileDescriptor(self, emu, fd):
        self._buffer.append(fd)

    @java_method_def(name='setDataPosition', args_list=['jint'], signature='(I)V', native=False)
    def setDataPosition(self, emu, pos):
        self._pos = pos

    @java_method_def(name='dataPosition', signature='()I', native=False)
    def dataPosition(self, emu):
        return self._pos

    @java_method_def(name='dataSize', signature='()I', native=False)
    def dataSize(self, emu):
        return len(self._buffer)

    @java_method_def(name='dataAvail', signature='()I', native=False)
    def dataAvail(self, emu):
        return max(0, len(self._buffer) - self._pos)

    @java_method_def(name='readException', signature='()V', native=False)
    def readException(self, emu):
        pass

    @java_method_def(name='readInt', signature='()I', native=False)
    def readInt(self, emu):
        if self._pos < len(self._buffer):
            val = self._buffer[self._pos]
            self._pos += 1
            if isinstance(val, int):
                return val
        return 0

    @java_method_def(name='readLong', signature='()J', native=False)
    def readLong(self, emu):
        if self._pos < len(self._buffer):
            val = self._buffer[self._pos]
            self._pos += 1
            if isinstance(val, int):
                return val
        return 0

    @java_method_def(name='readFloat', signature='()F', native=False)
    def readFloat(self, emu):
        if self._pos < len(self._buffer):
            val = self._buffer[self._pos]
            self._pos += 1
            if isinstance(val, (int, float)):
                return float(val)
        return 0.0

    @java_method_def(name='readDouble', signature='()D', native=False)
    def readDouble(self, emu):
        if self._pos < len(self._buffer):
            val = self._buffer[self._pos]
            self._pos += 1
            if isinstance(val, (int, float)):
                return float(val)
        return 0.0

    @java_method_def(name='readString', signature='()Ljava/lang/String;', native=False)
    def readString(self, emu):
        if self._pos < len(self._buffer):
            val = self._buffer[self._pos]
            self._pos += 1
            if isinstance(val, str):
                return String(val)
        return String("")

    @java_method_def(name='readStrongBinder', signature='()Landroid/os/IBinder;', native=False)
    def readStrongBinder(self, emu):
        if self._pos < len(self._buffer):
            val = self._buffer[self._pos]
            self._pos += 1
            return val
        return BinderProxy()

class IBinder(metaclass=JavaClassDef, jvm_name='android/os/IBinder'):
    def __init__(self):
        pass

    @java_method_def(
        name='transact',
        args_list=['jint', 'jobject', 'jobject', 'jint'],
        signature='(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z',
        native=False
    )
    def transact(self, emu, code, data, reply, flags):
        logger.warning("[IBinder] transact called: code=%d, flags=%d", code, flags)
        return True

    @java_method_def(name='queryLocalInterface', signature='(Ljava/lang/String;)Landroid/os/IInterface;', native=False)
    def queryLocalInterface(self, emu, descriptor):
        return None

    @java_method_def(name='isBinderAlive', signature='()Z', native=False)
    def isBinderAlive(self, emu):
        return True

    @java_method_def(name='pingBinder', signature='()Z', native=False)
    def pingBinder(self, emu):
        return True

    @java_method_def(name='getInterfaceDescriptor', signature='()Ljava/lang/String;', native=False)
    def getInterfaceDescriptor(self, emu):
        return String("android.os.IBinder")


class Binder(IBinder, metaclass=JavaClassDef, jvm_name='android/os/Binder', jvm_super=IBinder):
    def __init__(self):
        super().__init__()


class BinderProxy(IBinder, metaclass=JavaClassDef, jvm_name='android/os/BinderProxy', jvm_super=IBinder,
                  jvm_fields=[
                      JavaFieldDef('mObject', 'J', False, ignore=False),
                      JavaFieldDef('mSelf', 'Ljava/lang/ref/WeakReference;', False, ignore=True),
                  ]):
    def __init__(self, service_name: str = ""):
        super().__init__()
        self.service_name = service_name
        self.mObject = 0x1337BEEF

    @java_method_def(
        name='transact',
        args_list=['jint', 'jobject', 'jobject', 'jint'],
        signature='(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z',
        native=False
    )
    def transact(self, emu, code, data, reply, flags):
        logger.warning("[BinderProxy:%s] transact: code=%d, flags=%d", self.service_name or "unknown", code, flags)
        return True

    @java_method_def(
        name='transactNative',
        args_list=['jint', 'jobject', 'jobject', 'jint'],
        signature='(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z',
        native=False
    )
    def transactNative(self, emu, code, data, reply, flags):
        return True