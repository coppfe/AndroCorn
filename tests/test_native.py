import unittest
import logging
import time

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
    @java_method_def(name='leviathan', args_list=["jint", "jint", "jbyteArray"], signature='(II[B)[B', native=True)
    def leviathan(self, *args): pass

    @staticmethod
    @java_method_def(name='decode', args_list=["jint", "jbyteArray"], signature='(I[B)[B', native=True)
    def decode(self, *args): pass
    
    @staticmethod
    @java_method_def(name='encode', args_list=["jbyteArray"], signature='([B)[B', native=True)
    def encode(self, *args): pass

    @staticmethod
    @java_method_def(name='njss', args_list=["jint", "jobject"], signature='(ILjava/lang/Object;)Ljava/lang/Object;', native=False)
    def njss(*args): return None

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
        logging.getLogger().setLevel(logging.DEBUG)
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
    ps.print_stats(40)

    print(s.getvalue())

# INFO:root:process pid:4386
# INFO:root:[+] Detected Android property service (/dev/__properties__)
# INFO:root:[+] Initializing from build.prop
# INFO:androidemu.internal.linker:[Linker] Request to load: system/lib/libc.so (do_init=True) (main=False)
# INFO:androidemu.internal.linker:=== [Linker Phase 1] Loading Dependencies ===
# INFO:androidemu.internal.linker:=== [Linker Phase 2] TLS Bootstrap ===
# INFO:androidemu.internal.bionic.arm32.tls_bootstrap:[TLS-7.1-ARM32] Bootstrapping Legacy Layout
# INFO:androidemu.internal.bionic.arm32.tls_bootstrap:TLS 7.1 Ready. TP: 0x2000000, DTV: 0x2005000, Pthread: 0x2005610
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libc.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:  [TLS] Bootstrap done for libdl.so. TLS offset: 0x0
# INFO:androidemu.internal.linker:=== [Linker Phase 3] Relocations ===
# INFO:androidemu.internal.linker:=== [Linker Phase 4] Constructors ===
# INFO:androidemu.internal.linker:  [Init] libdl.so
# INFO:androidemu.internal.linker:  [Init] libc.so
# INFO:root:open [vfs//dev/__properties__][0xa8000] return fd 3
# WARNING:androidemu.native.sym_hooks.libdl_sym:[!] dlopen: library 'libnetd_client.so' NOT FOUND
# INFO:androidemu.internal.linker:[Linker] Request to load: libc.so (do_init=False) (main=False)
# INFO:androidemu.internal.linker:[Linker] Request to load: tests/bin/libcms.so (do_init=True) (main=True)
# INFO:androidemu.internal.linker:  [Init] libm.so
# INFO:androidemu.internal.linker:  [Init] liblog.so
# INFO:androidemu.internal.linker:  [Init] libstdc++.so
# INFO:androidemu.internal.linker:  [Init] libcms.so
# INFO:root:futext_wait call op=0x00000089 uaddr=0x70B7E960 *uaddr=0x00000002 val=0x00000002 timeout=0x00000000
# [*] Base address libcms: 0x400a0000
# [*] Calling leviathan Args: i1=-1, time=123456789, payload_len=13
# [*] Calling leviathan Args: i1=-1, time=123456789, payload_len=13
# Results for identical inputs: bytearray(b'\x04\x04 \xe0\x00\x10\x08\x8c9\xeb\xd5i\xdd\x03v}\xa6g\x06y\x86\r\x1a\xbbv\x10') bytearray(b'\x04\x04 \xe0\x00\x10\x08\x8c9\xeb\xd5i\xdd\x03v}\xa6g\x06y\x86\r\x1a\xbbv\x10')    
# .[*] Calling leviathan Args: i1=-1, time=1774953690, payload_len=0
# WARNING:root:'pipe2' not support. Using 'pipe'
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# WARNING:root:'pipe2' not support. Using 'pipe'
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# WARNING:root:'pipe2' not support. Using 'pipe'
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# WARNING:root:'pipe2' not support. Using 'pipe'
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# INFO:root:open [vfs//system/lib/libc.so][0x0] return fd 3
# INFO:root:open [vfs//system/lib/libc.so][0x0] return fd 3
# WARNING:root:'pipe2' not support. Using 'pipe'
# WARNING:root:syscall clone do fork...
# WARNING:root:Proxy call 'do_fork' is not support on Windows!!!
# INFO:root:open [vfs//system/lib/libc.so][0x0] return fd 3
# Result with empty payload: JavaArray(bytearray(b'\x04\x04 \xe0\x00\x10\xfc}\x06l!\xe6%@v}\xa6g\x06y\x86{t\xbd\xec\x00'))
# .[*] Calling leviathan Args: i1=-1, time=1, payload_len=59
# Result: bytearray(b"\x04\x04 \xe0\x00\x10;\'1\xaf\xff)\xf9a\xc8\xb66\xc8\x06y\x86\xed\xce\xa5e^")
# .
# ----------------------------------------------------------------------
# Ran 3 tests in 0.383s

# OK
#          203948 function calls (203700 primitive calls) in 0.387 seconds

#    Ordered by: cumulative time
#    List reduced from 993 to 40 due to restriction <40>

#    ncalls  tottime  percall  cumtime  percall filename:lineno(function)
#         1    0.000    0.000    0.387    0.387 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\main.py:65(__init__)
#         1    0.000    0.000    0.384    0.384 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\main.py:246(runTests)
#         1    0.000    0.000    0.384    0.384 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\runner.py:151(run)
#       2/1    0.000    0.000    0.383    0.383 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\suite.py:83(__call__)
#       2/1    0.000    0.000    0.383    0.383 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\suite.py:102(run)
#        16    0.000    0.000    0.279    0.017 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:261(call_native)
#        16    0.000    0.000    0.279    0.017 c:\Users\Kirill\Desktop\androidemu\androidemu\scheduler.py:156(call_native)
#        16    0.000    0.000    0.279    0.017 c:\Users\Kirill\Desktop\androidemu\androidemu\scheduler.py:139(exec)
#        16    0.000    0.000    0.278    0.017 c:\Users\Kirill\Desktop\androidemu\androidemu\scheduler.py:164(__run_scheduler_loop)
#        22    0.213    0.010    0.278    0.013 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\site-packages\unicorn\unicorn.py:315(emu_start)
#         3    0.000    0.000    0.202    0.067 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\case.py:735(__call__)
#         3    0.000    0.000    0.202    0.067 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\case.py:641(run)
#         3    0.000    0.000    0.202    0.067 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\case.py:632(_callTestMethod)
#         4    0.000    0.000    0.201    0.050 c:/Users/Kirill/Desktop/androidemu/test_libcms.py:63(call_leviathan)
#         1    0.000    0.000    0.185    0.185 c:/Users/Kirill/Desktop/androidemu/test_libcms.py:137(test_leviathan_empty_payload)
#         3    0.000    0.000    0.181    0.060 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\unittest\suite.py:142(_handleClassSetUp)
#         1    0.000    0.000    0.181    0.181 c:/Users/Kirill/Desktop/androidemu/test_libcms.py:115(setUpClass)
#         1    0.000    0.000    0.181    0.181 c:/Users/Kirill/Desktop/androidemu/test_libcms.py:101(init)
#         3    0.000    0.000    0.158    0.053 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:117(load_module)
#         1    0.000    0.000    0.097    0.097 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:151(__init__)
#         2    0.000    0.000    0.080    0.040 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:234(load_library)
#         2    0.000    0.000    0.080    0.040 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:154(_pipeline_dlopen)
#         1    0.000    0.000    0.078    0.078 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:141(__init_syslibs)
#         1    0.000    0.000    0.077    0.077 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:133(_pipeline_load_executable)
#         2    0.000    0.000    0.076    0.038 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:283(_initialize_graph)
#      12/2    0.000    0.000    0.076    0.038 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:287(visit)
#         6    0.000    0.000    0.076    0.013 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:300(_call_constructors)
#      13/3    0.000    0.000    0.045    0.015 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:189(_load_recursive)
#       717    0.000    0.000    0.044    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\site-packages\unicorn\unicorn.py:492(_hook_intr_cb)
#       717    0.001    0.000    0.044    0.000 c:\Users\Kirill\Desktop\androidemu\androidemu\kernel\syscalls\interrupt_handler.py:25(_hook_interrupt)
#       717    0.003    0.000    0.043    0.000 c:\Users\Kirill\Desktop\androidemu\androidemu\kernel\syscalls\syscall_handlers.py:34(_handle_syscall)
#         6    0.005    0.001    0.039    0.007 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\elf_reader.py:11(__init__)
#         6    0.008    0.001    0.035    0.006 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\linker.py:243(_relocate_module)
#         6    0.030    0.005    0.033    0.005 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\elf_reader.py:93(_parse_functions)
#      1047    0.000    0.000    0.021    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\site-packages\unicorn\unicorn.py:477(_hookcode_cb)
#      1047    0.001    0.000    0.020    0.000 c:\Users\Kirill\Desktop\androidemu\androidemu\hooker.py:85(_hook)
#      1047    0.002    0.000    0.019    0.000 c:\Users\Kirill\Desktop\androidemu\androidemu\java\helpers\native_method.py:106(native_method_wrapper)
#      7080    0.009    0.000    0.015    0.000 C:\Users\Kirill\AppData\Local\Programs\Python\Python38\lib\site-packages\unicorn\unicorn.py:432(mem_read)
#      2987    0.002    0.000    0.015    0.000 c:\Users\Kirill\Desktop\androidemu\androidemu\internal\relocator.py:50(apply)
#         1    0.000    0.000    0.013    0.013 c:\Users\Kirill\Desktop\androidemu\androidemu\emulator.py:57(__add_classes)

