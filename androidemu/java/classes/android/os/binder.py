from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def
from androidemu.java.classes.java.lang.string import String

class Parcel(metaclass=JavaClassDef, jvm_name='android/os/Parcel'):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='obtain', signature='()Landroid/os/Parcel;', native=False)
    def obtain(emu):
        return Parcel()

    @java_method_def(name='recycle', signature='()V', native=False)
    def recycle(self, emu):
        pass


class IBinder(metaclass=JavaClassDef, jvm_name='android/os/IBinder'):
    pass

class Binder(metaclass=JavaClassDef, jvm_name='android/os/Binder', jvm_super=IBinder):
    pass

class BinderProxy(metaclass=JavaClassDef, jvm_name='android/os/BinderProxy', jvm_super=IBinder,
                  jvm_fields=[
                      JavaFieldDef('mObject', 'J', False, ignore=False),
                      JavaFieldDef('mSelf', 'Ljava/lang/ref/WeakReference;', False, ignore=True),
                  ]):
    def __init__(self):
        super().__init__()
        self.mObject = 0x1337BEEF

    @java_method_def(
        name='transactNative',
        args_list=['jint', 'jobject', 'jobject', 'jint'],
        signature='(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z',
        native=False
    )
    def transactNative(self, emu, code, data, reply, flags):
        return True

    @java_method_def(
        name='transact',
        args_list=['jint', 'jobject', 'jobject', 'jint'],
        signature='(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z',
        native=False
    )
    def transact(self, emu, code, data, reply, flags):
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