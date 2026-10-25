import logging
from typing import TYPE_CHECKING

from ...native.helpers.method import native_method
from ..jni.constants import *
from ..jni.main import JNIEnv
from ..jni.reference import jobject

if TYPE_CHECKING:
    from androidemu import Emulator
    from androidemu.utils.hooker import Hooker
    from androidemu.java.classloader import JavaClassLoader

logger = logging.getLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:
    address_ptr: int
    address: int

    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """

    # External API
    def throw_exception(self, exc_obj):
        self.jni_env.throw_exception(jobject(exc_obj))

    def __init__(self, emu: 'Emulator', class_loader: 'JavaClassLoader', hooker: 'Hooker'):

        (self.address_ptr, self.address) = hooker.write_function_table({
            3: self.destroy_java_vm,
            4: self.attach_current_thread,
            5: self.detach_current_thread,
            6: self.get_env,
            7: self.attach_current_thread
        })

        self.jni_env = JNIEnv(emu, class_loader, hooker)

    @native_method
    def destroy_java_vm(self, emu: 'Emulator'):
        raise RuntimeError("The fuck you mean destroy VM?")

    @native_method
    def attach_current_thread(self, emu: 'Emulator', java_vm, env_ptr, thr_args):
        emu.memory.write_ptr(env_ptr, self.jni_env.address_ptr)
        return JNI_OK

    @native_method
    def detach_current_thread(self, emu: 'Emulator', java_vm):
        # TODO: NooOO idea.
        return JNI_OK

    @native_method
    def get_env(self, emu: 'Emulator', java_vm, env_ptr, version):
        emu.memory.write_ptr(env_ptr, self.jni_env.address_ptr)
        return JNI_OK

    @native_method
    def attach_current_thread_as_daemon(self, emu: 'Emulator', java_vm, env_ptr, thr_args):
        emu.memory.write_ptr(env_ptr, self.jni_env.address_ptr)
        return JNI_OK