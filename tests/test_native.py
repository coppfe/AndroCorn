import unittest
import time
import logging

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.array import ByteArray
from androidemu.java.jni_ref import jobject
from androidemu.java.classes.list import List

from unicorn import *
from unicorn.arm_const import *

class com_ss_sys_ces_a(metaclass=JavaClassDef, jvm_name='com/ss/sys/ces/a'):
    @staticmethod
    @java_method_def(name='meta', args_list=["jint", "jobject", "jobject"], signature='(ILandroid/content/Context;Ljava/lang/Object;)Ljava/lang/Object;', native=True)
    def meta(self, *args): pass
    
    @staticmethod
    @java_method_def(name='leviathan', args_list=["jint", "jint", "jobject"], signature='(II[B)[B', native=True)
    def leviathan(self, *args): pass

    @staticmethod
    @java_method_def(name='decode', args_list=["jint", "jobject"], signature='(I[B)[B', native=True)
    def decode(self, *args): pass
    
    @staticmethod
    @java_method_def(name='encode', args_list=["jobject"], signature='([B)[B', native=True)
    def encode(self, *args): pass

    @staticmethod
    @java_method_def(name='njss', args_list=["jint", "jobject"], signature='(ILjava/lang/Object;)Ljava/lang/Object;', native=False)
    def njss(emu, i1, s):
        # just stub it idk what this shit want. if you want to check reverse older versions of tiktok (overland) like <20.x.x
        if i1 == 136:
            return ByteArray([])
        elif i1 == 235:
            pass

    @staticmethod
    @java_method_def(name='Bill', args_list=[], signature='()V', native=False)
    def Bill(*args): pass

    @staticmethod
    @java_method_def(name='Francies', args_list=[], signature='()V', native=False)
    def Francies(*args): pass

    @staticmethod
    @java_method_def(name='Louis', args_list=[], signature='()V', native=False)
    def Louis(*args): pass
    
    @staticmethod
    @java_method_def(name='Zeoy', args_list=[], signature='()V', native=False)
    def Zeoy(*args): pass

    # hello from left 4 dead?

class java_lang_Thread(metaclass=JavaClassDef, jvm_name='java/lang/Thread'):
    @java_method_def(name="currentThread", signature='()Ljava/lang/Thread;', native=False)
    def currentThread(self):
        return java_lang_Thread()

    @java_method_def(name="getStackTrace", signature='()[Ljava/lang/StackTraceElement;', native=False)
    def getStackTrace(self, s):
        return List([])
    
def malloc_handler(emu, size):
    print(f"[*] Malloc: {size}")

def call_leviathan(emulator: Emulator, i1, timestamp, payload_bytes):
    jni_env = emulator.java_vm.jni_env
    
    clazz = emulator.java_classloader.find_class_by_name("com/ss/sys/ces/a")
    jclass_ptr = clazz.jvm_id

    method = iter(clazz.jvm_methods.values())

    for m in method:
        if m.name == "leviathan":
            method = m

    call_addr = method.native_addr | 1

    payload = ByteArray(payload_bytes)
    payload_ref = jni_env.add_local_reference(jobject(payload))

    print(f"[*] Calling leviathan Args: i1={i1}, time={timestamp}, payload_len={len(payload_bytes)}")

    # R0 = JNIEnv*
    # R1 = jclass
    # R2 = jint i1
    # R3 = jint time
    # R4 = jbyteArray payload
    result_ptr = emulator.call_native(
        call_addr,
        jni_env.address_ptr,
        jclass_ptr,
        i1,
        timestamp,
        payload_ref
    )
    
    if result_ptr:
        res_obj = jni_env.get_reference(result_ptr)
        return res_obj.value
    return None

def init():
    emulator = Emulator(vfs_root="vfs", muti_task=True, arch=1)
    
    emulator.java_classloader.add_class(com_ss_sys_ces_a)
    emulator.java_classloader.add_class(java_lang_Thread)
    
    libml = emulator.load_library(f"tests/bin/libcms.so", do_init=True, main_lib=True)
    print(f"[*] Base address libcms: {hex(libml.base)}")

    emulator.call_symbol(libml, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
    
    return emulator

class TestLeviathanJNI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # logging.getLogger().setLevel(logging.DEBUG) # set debug level if u want to die
        cls.emulator = init()

    def test_leviathan_standard_call(self):
        test_time = 1
        test_payload = b'{"os":"Android","version":"9","fake_device_id":"123456789"}'
        result = call_leviathan(
            self.emulator, 
            i1=-1, 
            timestamp=test_time, 
            payload_bytes=test_payload
        )
        
        self.assertIsNotNone(result, "Leviathan returned None for valid input")
        
        res_items = result.get_py_items()
        print(f"Result: {res_items}")
        self.assertGreater(len(res_items), 0, "Result byte array is empty")

    def test_leviathan_empty_payload(self):
        result = call_leviathan(
            self.emulator, 
            i1=-1, 
            timestamp=int(time.time()), 
            payload_bytes=b''
        )
        # hmmmm why are u so bitch when i asking u to handle empty payload
        print(f"Result with empty payload: {result}")
        self.assertIsNotNone(result, "Leviathan should handle empty payload")

    def test_leviathan_consistency(self):
        test_payload = b"constant_data"
        ts = 123456789
        
        res1 = call_leviathan(self.emulator, -1, ts, test_payload).get_py_items()
        res2 = call_leviathan(self.emulator, -1, ts, test_payload).get_py_items()

        print(f"Results for identical inputs: {res1} {res2}")
        
        self.assertEqual(res1, res2, "Results for identical inputs must be equal")

if __name__ == '__main__':
    import cProfile
    import pstats
    import io

    pr = cProfile.Profile()
    pr.enable()
    unittest.main(exit=False)
    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    print(s.getvalue())

# Execve hit log level changed to debug

# Fork Task is TOOOOOOOOOOOOOOOOOOO SLOW

# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# [*] Base address libcms: 0x400c0000
# [*] Calling leviathan Args: i1=-1, time=123456789, payload_len=13
# [*] Calling leviathan Args: i1=-1, time=123456789, payload_len=13
# Results for identical inputs: bytearray(b'\x04\x04\x00\xe0\x00\x10=\xcf\xf2A\xa5\xbbu[\xd3p\xc9OZj\xc3m\xd1(\x9cU') bytearray(b'\x04\x04\x00\xe0\x00\x10=\xcf\xf2A\xa5\xbbu[\xd3p\xc9OZj\xc3m\xd1(\x9cU')
# .[*] Calling leviathan Args: i1=-1, time=1777585171, payload_len=0
# WARNING:root:syscall clone do fork...
# WARNING:root:syscall clone do fork...
# WARNING:root:syscall clone do fork...
# WARNING:root:syscall clone do fork...
# WARNING:root:syscall clone do fork...
# WARNING:root:syscall clone do fork...
# WARNING:root:syscall clone do fork...
# WARNING:root:syscall clone do fork...
# WARNING:root:Failed to open file ''! It's a directory
# WARNING:root:Failed to open file ''! It's a directory
# WARNING:root:syscall clone do fork...
# WARNING:root:Failed to open file ''! It's a directory
# WARNING:root:Failed to open file ''! It's a directory
# Result with empty payload: JavaArray(bytearray(b'\x04\x04 \xe0\x00\x10\xfc}\x06`\xd5i\xdd\x03v}\xa6g\x06y\x86{hj\x1e9'))
# .[*] Calling leviathan Args: i1=-1, time=1, payload_len=59
# Result: bytearray(b"\x04\x04 \xe0\x00\x10;\'1\xaf\xff)\xf9a\xc8\xb66\xc8\x06y\x86\xed\xce\xa5e^")
# .
# ----------------------------------------------------------------------
# Ran 3 tests in 0.814s

# OK
#          315539 function calls (315200 primitive calls) in 0.819 seconds

#    Ordered by: cumulative time
#    List reduced from 1105 to 40 due to restriction <40>

#    ncalls  tottime  percall  cumtime  percall filename:lineno(function)
#         1    0.000    0.000    0.819    0.819 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/main.py:66(__init__)
#         1    0.000    0.000    0.814    0.814 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/main.py:249(runTests)
#         1    0.000    0.000    0.814    0.814 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/runner.py:192(run)
#       2/1    0.000    0.000    0.814    0.814 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/suite.py:83(__call__)
#       2/1    0.000    0.000    0.814    0.814 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/suite.py:102(run)
#        16    0.000    0.000    0.714    0.045 /home/coppfe/Desktop/androidemu/androidemu/emulator.py:382(call_native)
#        16    0.000    0.000    0.714    0.045 /home/coppfe/Desktop/androidemu/androidemu/scheduler.py:374(call_native)
#        16    0.000    0.000    0.714    0.045 /home/coppfe/Desktop/androidemu/androidemu/scheduler.py:350(exec)
#        16    0.001    0.000    0.713    0.045 /home/coppfe/Desktop/androidemu/androidemu/scheduler.py:390(__run_scheduler_loop)
#        46    0.543    0.012    0.707    0.015 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/site-packages/unicorn/unicorn_py3/unicorn.py:748(emu_start)
#         3    0.000    0.000    0.564    0.188 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/case.py:677(__call__)
#         3    0.000    0.000    0.564    0.188 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/case.py:589(run)
#         3    0.000    0.000    0.564    0.188 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/case.py:578(_callTestMethod)
#         4    0.000    0.000    0.564    0.141 /home/coppfe/Desktop/androidemu/test_native.py:68(call_leviathan)
#         1    0.000    0.000    0.548    0.548 /home/coppfe/Desktop/androidemu/test_native.py:141(test_leviathan_empty_payload)
#         3    0.000    0.000    0.249    0.083 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/unittest/suite.py:142(_handleClassSetUp)
#         1    0.000    0.000    0.249    0.249 /home/coppfe/Desktop/androidemu/test_native.py:120(setUpClass)
#         1    0.000    0.000    0.249    0.249 /home/coppfe/Desktop/androidemu/test_native.py:106(init)
#         2    0.000    0.000    0.227    0.113 /home/coppfe/Desktop/androidemu/androidemu/emulator.py:312(load_library)
#         2    0.000    0.000    0.227    0.113 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:104(load_module)
#      1875    0.002    0.000    0.164    0.000 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/site-packages/unicorn/unicorn_py3/unicorn.py:360(wrapper)
#         2    0.000    0.000    0.146    0.073 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:280(_initialize_graph)
#      12/2    0.000    0.000    0.146    0.073 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:284(visit)
#         6    0.000    0.000    0.146    0.024 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:297(_call_constructors)
#         1    0.000    0.000    0.144    0.144 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:143(_pipeline_dlopen)
#       814    0.000    0.000    0.117    0.000 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/site-packages/unicorn/unicorn_py3/unicorn.py:1048(__hook_intr_cb)
#       814    0.001    0.000    0.117    0.000 /home/coppfe/Desktop/androidemu/androidemu/handlers/interrupt.py:25(_hook_interrupt)
#       814    0.006    0.000    0.116    0.000 /home/coppfe/Desktop/androidemu/androidemu/handlers/syscall.py:34(_handle_syscall)
#         1    0.000    0.000    0.100    0.100 /home/coppfe/Desktop/androidemu/androidemu/emulator.py:189(__init__)
#         1    0.000    0.000    0.083    0.083 /home/coppfe/Desktop/androidemu/androidemu/emulator.py:170(__init_syslibs)
#         1    0.000    0.000    0.083    0.083 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:122(_pipeline_load_executable)
#      1061    0.000    0.000    0.044    0.000 /home/coppfe/.pyenv/versions/3.11.6/lib/python3.11/site-packages/unicorn/unicorn_py3/unicorn.py:1061(__hook_code_cb)
#      1061    0.002    0.000    0.044    0.000 /home/coppfe/Desktop/androidemu/androidemu/hooker.py:96(_hook)
#         6    0.010    0.002    0.042    0.007 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:240(_relocate_module)
#      1061    0.004    0.000    0.042    0.000 /home/coppfe/Desktop/androidemu/androidemu/java/helpers/native_method.py:106(native_method_wrapper)
#      12/2    0.001    0.000    0.037    0.018 /home/coppfe/Desktop/androidemu/androidemu/internal/linker.py:178(_load_recursive)
#        10    0.000    0.000    0.036    0.004 /home/coppfe/Desktop/androidemu/androidemu/kernel/syscalls/syscall_base/logic/process.py:85(_clone)
#        10    0.000    0.000    0.036    0.004 /home/coppfe/Desktop/androidemu/androidemu/kernel/syscalls/syscall_base/logic/helpers/process_helper.py:39(_clone)
#         9    0.000    0.000    0.034    0.004 /home/coppfe/Desktop/androidemu/androidemu/kernel/syscalls/syscall_base/logic/helpers/process_helper.py:20(_do_fork)
#         9    0.021    0.002    0.034    0.004 /home/coppfe/Desktop/androidemu/androidemu/scheduler.py:117(fork_task)