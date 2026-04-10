import logging
import struct

from ..jni_ref import *

from ..constants.jni_const import *
from ..constants.default_const import JAVA_NULL
from unicorn import *

from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from ..jni_env import JNIEnv

def read_args32(jni: 'JNIEnv', mu: 'Uc', args: List, args_type_list: List) -> List:
    if not args_type_list: return []
    
    result = []
    idx = 0
    n = len(args)
    get_ref = jni.get_reference

    for t in args_type_list:
        if idx >= n: break
        
        if t[1] == 'l' or t[1] == 'd': # jlong, jdouble
            idx += (3 + idx) & 1
            if idx + 1 >= n: break
            
            v = (args[idx+1] << 32) | (args[idx] & 0xFFFFFFFF)
            if t[1] == 'l' and v >> 63: v -= 1 << 64
            
            result.append(v)
            idx += 2
        elif t[1] == 's' or t[1] == 'o': # jstring, jobject
            ref = get_ref(args[idx])
            result.append(JAVA_NULL if ref is None else ref.value)
            idx += 1
        else: # jint, jchar, jbyte, jboolean
            result.append(args[idx])
            idx += 1
            
    return result

def read_args64(jni: 'JNIEnv', mu: 'Uc', args: List, args_type_list: List) -> List:
    if not args_type_list: return []

    result = []
    get_ref = jni.get_reference
    for i in range(len(args_type_list) if len(args_type_list) < len(args) else len(args)):
        t = args_type_list[i]
        v = args[i]
        
        # 's' - jstring, 'o' - jobject.
        if t[1] == 's' or t[1] == 'o':
            ref = get_ref(v)
            result.append(JAVA_NULL if ref is None else ref.value)
        else:
            result.append(v)
            
    return result
def read_args_v32(jni: 'JNIEnv', mu: 'Uc', args_ptr, args_type_list) -> List:
    if not args_type_list: return []
    
    res = []
    p = args_ptr
    get_ref = jni.get_reference
    read = mu.mem_read

    for t in args_type_list:
        c = t[1]
        if c == 'l' or c == 'd': # jlong, jdouble
            p += p & 4
            v = struct.unpack('<q' if c == 'l' else '<Q', read(p, 8))[0]
            res.append(v)
            p += 8
        elif c == 's' or c == 'o': # jstring, jobject
            v = struct.unpack('<I', read(p, 4))[0]
            ref = get_ref(v)
            res.append(JAVA_NULL if ref is None else ref.value)
            p += 4
        else: # jint, jchar, jbyte, jboolean
            res.append(struct.unpack('<I', read(p, 4))[0])
            p += 4
            
    return res

def read_args_v64(jni: 'JNIEnv', mu: 'Uc', args_ptr: int, args_type_list: List) -> List:
    if not args_type_list: return []
    
    # __stack(Q), __gr_top(Q), __vr_top(Q), __gr_offs(i), __vr_offs(i)
    stk, gr_t, vr_t, gr_o, vr_o = struct.unpack("<QQQii", mu.mem_read(args_ptr, 32))
    
    res = []
    read = mu.mem_read
    get_ref = jni.get_reference

    for t in args_type_list:
        c = t[1]
        # jdouble (d) jfloat (f) using VR
        if c == 'd' or c == 'f':
            if vr_o >= 0:
                addr = stk
                stk += 8
            else:
                addr = vr_t + vr_o
                vr_o += 16 # VR args in AAPCS64 using 16 bytes (Q-reg)
            
            v = struct.unpack("<Q", read(addr, 8))[0]
            res.append(v)
        else:
            # (int, long, object, etc)
            if gr_o >= 0:
                addr = stk
                stk += 8
            else:
                addr = gr_t + gr_o
                gr_o += 8
            
            v = struct.unpack("<Q", read(addr, 8))[0]
            
            if c == 's' or c == 'o': # jstring, jobject
                if v == 0:
                    res.append(JAVA_NULL)
                else:
                    ref = get_ref(v)
                    res.append(JAVA_NULL if ref is None else ref.value)
            else:
                res.append(v)
                
    return res