import logging

from ...native.helpers.method import native_method
from ..jni.constants import *
from ..jni.main import JNIEnv

from ...types import ptr_t

logger = logging.getLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:

    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """
    def __init__(self, emu, class_loader, hooker):
        (self.address_ptr, self.address) = hooker.write_function_table({
            3: self.destroy_java_vm,
            4: self.attach_current_thread,
            5: self.detach_current_thread,
            6: self.get_env,
            7: self.attach_current_thread
        })

        self.jni_env = JNIEnv(emu, class_loader, hooker)
    #

    @native_method
    def destroy_java_vm(self, emu):
        raise NotImplementedError()
    #
    
    @native_method
    def attach_current_thread(self, emu, java_vm, env_ptr, thr_args):
        emu.mu.mem_write(env_ptr, self.jni_env.address_ptr.to_bytes(ptr_t.size, byteorder='little'))
        return JNI_OK
    #

    @native_method
    def detach_current_thread(self, emu, java_vm):
        # TODO: NooOO idea.
        return JNI_OK
    #

    @native_method
    def get_env(self, emu, java_vm, env_ptr, version):
        emu.mu.mem_write(env_ptr, self.jni_env.address_ptr.to_bytes(ptr_t.size, byteorder='little'))
        return JNI_OK
    #

    @native_method
    def attach_current_thread_as_daemon(self, emu, java_vm, env_ptr, thr_args):
        emu.mu.mem_write(env_ptr, self.jni_env.address_ptr.to_bytes(ptr_t.size, byteorder='little'))
        return JNI_OK
    #

