import re

def convert(name):
    name = name.strip().replace(',', '')
    if name == "NULL": return "reserved"
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

table_raw = """
    NULL, NULL, NULL, NULL, GetVersion, DefineClass, FindClass, FromReflectedMethod,
    FromReflectedField, ToReflectedMethod, GetSuperclass, IsAssignableFrom, ToReflectedField,
    Throw, ThrowNew, ExceptionOccurred, ExceptionDescribe, ExceptionClear, FatalError,
    PushLocalFrame, PopLocalFrame, NewGlobalRef, DeleteGlobalRef, DeleteLocalRef, IsSameObject,
    NewLocalRef, EnsureLocalCapacity, AllocObject, NewObject, NewObjectV, NewObjectA,
    GetObjectClass, IsInstanceOf, GetMethodID, CallObjectMethod, CallObjectMethodV,
    CallObjectMethodA, CallBooleanMethod, CallBooleanMethodV, CallBooleanMethodA,
    CallByteMethod, CallByteMethodV, CallByteMethodA, CallCharMethod, CallCharMethodV,
    CallCharMethodA, CallShortMethod, CallShortMethodV, CallShortMethodA, CallIntMethod,
    CallIntMethodV, CallIntMethodA, CallLongMethod, CallLongMethodV, CallLongMethodA,
    CallFloatMethod, CallFloatMethodV, CallFloatMethodA, CallDoubleMethod, CallDoubleMethodV,
    CallDoubleMethodA, CallVoidMethod, CallVoidMethodV, CallVoidMethodA,
    CallNonvirtualObjectMethod, CallNonvirtualObjectMethodV, CallNonvirtualObjectMethodA,
    CallNonvirtualBooleanMethod, CallNonvirtualBooleanMethodV, CallNonvirtualBooleanMethodA,
    CallNonvirtualByteMethod, CallNonvirtualByteMethodV, CallNonvirtualByteMethodA,
    CallNonvirtualCharMethod, CallNonvirtualCharMethodV, CallNonvirtualCharMethodA,
    CallNonvirtualShortMethod, CallNonvirtualShortMethodV, CallNonvirtualShortMethodA,
    CallNonvirtualIntMethod, CallNonvirtualIntMethodV, CallNonvirtualIntMethodA,
    CallNonvirtualLongMethod, CallNonvirtualLongMethodV, CallNonvirtualLongMethodA,
    CallNonvirtualFloatMethod, CallNonvirtualFloatMethodV, CallNonvirtualFloatMethodA,
    CallNonvirtualDoubleMethod, CallNonvirtualDoubleMethodV, CallNonvirtualDoubleMethodA,
    CallNonvirtualVoidMethod, CallNonvirtualVoidMethodV, CallNonvirtualVoidMethodA,
    GetFieldID, GetObjectField, GetBooleanField, GetByteField, GetCharField, GetShortField,
    GetIntField, GetLongField, GetFloatField, GetDoubleField, SetObjectField, SetBooleanField,
    SetByteField, SetCharField, SetShortField, SetIntField, SetLongField, SetFloatField,
    SetDoubleField, GetStaticMethodID, CallStaticObjectMethod, CallStaticObjectMethodV,
    CallStaticObjectMethodA, CallStaticBooleanMethod, CallStaticBooleanMethodV,
    CallStaticBooleanMethodA, CallStaticByteMethod, CallStaticByteMethodV, CallStaticByteMethodA,
    CallStaticCharMethod, CallStaticCharMethodV, CallStaticCharMethodA, CallStaticShortMethod,
    CallStaticShortMethodV, CallStaticShortMethodA, CallStaticIntMethod, CallStaticIntMethodV,
    CallStaticIntMethodA, CallStaticLongMethod, CallStaticLongMethodV, CallStaticLongMethodA,
    CallStaticFloatMethod, CallStaticFloatMethodV, CallStaticFloatMethodA, CallStaticDoubleMethod,
    CallStaticDoubleMethodV, CallStaticDoubleMethodA, CallStaticVoidMethod, CallStaticVoidMethodV,
    CallStaticVoidMethodA, GetStaticFieldID, GetStaticObjectField, GetStaticBooleanField,
    GetStaticByteField, GetStaticCharField, GetStaticShortField, GetStaticIntField,
    GetStaticLongField, GetStaticFloatField, GetStaticDoubleField, SetStaticObjectField,
    SetStaticBooleanField, SetStaticByteField, SetStaticCharField, SetStaticShortField,
    SetStaticIntField, SetStaticLongField, SetStaticFloatField, SetStaticDoubleField,
    NewString, GetStringLength, GetStringChars, ReleaseStringChars, NewStringUTF,
    GetStringUTFLength, GetStringUTFChars, ReleaseStringUTFChars, GetArrayLength,
    NewObjectArray, GetObjectArrayElement, SetObjectArrayElement, NewBooleanArray,
    NewByteArray, NewCharArray, NewShortArray, NewIntArray, NewLongArray, NewFloatArray,
    NewDoubleArray, GetBooleanArrayElements, GetByteArrayElements, GetCharArrayElements,
    GetShortArrayElements, GetIntArrayElements, GetLongArrayElements, GetFloatArrayElements,
    GetDoubleArrayElements, ReleaseBooleanArrayElements, ReleaseByteArrayElements,
    ReleaseCharArrayElements, ReleaseShortArrayElements, ReleaseIntArrayElements,
    ReleaseLongArrayElements, ReleaseFloatArrayElements, ReleaseDoubleArrayElements,
    GetBooleanArrayRegion, GetByteArrayRegion, GetCharArrayRegion, GetShortArrayRegion,
    GetIntArrayRegion, GetLongArrayRegion, GetFloatArrayRegion, GetDoubleArrayRegion,
    SetBooleanArrayRegion, SetByteArrayRegion, SetCharArrayRegion, SetShortArrayRegion,
    SetIntArrayRegion, SetLongArrayRegion, SetFloatArrayRegion, SetDoubleArrayRegion,
    RegisterNatives, UnregisterNatives, MonitorEnter, MonitorExit, GetJavaVM,
    GetStringRegion, GetStringUTFRegion, GetPrimitiveArrayCritical, ReleasePrimitiveArrayCritical,
    GetStringCritical, ReleaseStringCritical, NewWeakGlobalRef, DeleteWeakGlobalRef,
    ExceptionCheck, NewDirectByteBuffer, GetDirectBufferAddress, GetDirectBufferCapacity,
    GetObjectRefType
"""

entries = [e.strip() for e in table_raw.replace('\n', ' ').split(',') if e.strip()]

print("# --- JNI MAP TABLE ---")
for i, name in enumerate(entries):
    offset = i * 4
    func_name = convert(name)
    print(f"Index: {i:3} | Offset: 0x{offset:03x} | {name} -> {func_name}")

# --- JNI MAP TABLE ---
# Index:   0 | Offset: 0x000 | NULL -> reserved
# Index:   1 | Offset: 0x004 | NULL -> reserved
# Index:   2 | Offset: 0x008 | NULL -> reserved
# Index:   3 | Offset: 0x00c | NULL -> reserved
# Index:   4 | Offset: 0x010 | GetVersion -> get_version
# Index:   5 | Offset: 0x014 | DefineClass -> define_class
# Index:   6 | Offset: 0x018 | FindClass -> find_class
# Index:   7 | Offset: 0x01c | FromReflectedMethod -> from_reflected_method
# Index:   8 | Offset: 0x020 | FromReflectedField -> from_reflected_field
# Index:   9 | Offset: 0x024 | ToReflectedMethod -> to_reflected_method
# Index:  10 | Offset: 0x028 | GetSuperclass -> get_superclass
# Index:  11 | Offset: 0x02c | IsAssignableFrom -> is_assignable_from
# Index:  12 | Offset: 0x030 | ToReflectedField -> to_reflected_field
# Index:  13 | Offset: 0x034 | Throw -> throw
# Index:  14 | Offset: 0x038 | ThrowNew -> throw_new
# Index:  15 | Offset: 0x03c | ExceptionOccurred -> exception_occurred
# Index:  16 | Offset: 0x040 | ExceptionDescribe -> exception_describe
# Index:  17 | Offset: 0x044 | ExceptionClear -> exception_clear
# Index:  18 | Offset: 0x048 | FatalError -> fatal_error
# Index:  19 | Offset: 0x04c | PushLocalFrame -> push_local_frame
# Index:  20 | Offset: 0x050 | PopLocalFrame -> pop_local_frame
# Index:  21 | Offset: 0x054 | NewGlobalRef -> new_global_ref
# Index:  22 | Offset: 0x058 | DeleteGlobalRef -> delete_global_ref
# Index:  23 | Offset: 0x05c | DeleteLocalRef -> delete_local_ref
# Index:  24 | Offset: 0x060 | IsSameObject -> is_same_object
# Index:  25 | Offset: 0x064 | NewLocalRef -> new_local_ref
# Index:  26 | Offset: 0x068 | EnsureLocalCapacity -> ensure_local_capacity
# Index:  27 | Offset: 0x06c | AllocObject -> alloc_object
# Index:  28 | Offset: 0x070 | NewObject -> new_object
# Index:  29 | Offset: 0x074 | NewObjectV -> new_object_v
# Index:  30 | Offset: 0x078 | NewObjectA -> new_object_a
# Index:  31 | Offset: 0x07c | GetObjectClass -> get_object_class
# Index:  32 | Offset: 0x080 | IsInstanceOf -> is_instance_of
# Index:  33 | Offset: 0x084 | GetMethodID -> get_method_id
# Index:  34 | Offset: 0x088 | CallObjectMethod -> call_object_method
# Index:  35 | Offset: 0x08c | CallObjectMethodV -> call_object_method_v
# Index:  36 | Offset: 0x090 | CallObjectMethodA -> call_object_method_a
# Index:  37 | Offset: 0x094 | CallBooleanMethod -> call_boolean_method
# Index:  38 | Offset: 0x098 | CallBooleanMethodV -> call_boolean_method_v
# Index:  39 | Offset: 0x09c | CallBooleanMethodA -> call_boolean_method_a
# Index:  40 | Offset: 0x0a0 | CallByteMethod -> call_byte_method
# Index:  41 | Offset: 0x0a4 | CallByteMethodV -> call_byte_method_v
# Index:  42 | Offset: 0x0a8 | CallByteMethodA -> call_byte_method_a
# Index:  43 | Offset: 0x0ac | CallCharMethod -> call_char_method
# Index:  44 | Offset: 0x0b0 | CallCharMethodV -> call_char_method_v
# Index:  45 | Offset: 0x0b4 | CallCharMethodA -> call_char_method_a
# Index:  46 | Offset: 0x0b8 | CallShortMethod -> call_short_method
# Index:  47 | Offset: 0x0bc | CallShortMethodV -> call_short_method_v
# Index:  48 | Offset: 0x0c0 | CallShortMethodA -> call_short_method_a
# Index:  49 | Offset: 0x0c4 | CallIntMethod -> call_int_method
# Index:  50 | Offset: 0x0c8 | CallIntMethodV -> call_int_method_v
# Index:  51 | Offset: 0x0cc | CallIntMethodA -> call_int_method_a
# Index:  52 | Offset: 0x0d0 | CallLongMethod -> call_long_method
# Index:  53 | Offset: 0x0d4 | CallLongMethodV -> call_long_method_v
# Index:  54 | Offset: 0x0d8 | CallLongMethodA -> call_long_method_a
# Index:  55 | Offset: 0x0dc | CallFloatMethod -> call_float_method
# Index:  56 | Offset: 0x0e0 | CallFloatMethodV -> call_float_method_v
# Index:  57 | Offset: 0x0e4 | CallFloatMethodA -> call_float_method_a
# Index:  58 | Offset: 0x0e8 | CallDoubleMethod -> call_double_method
# Index:  59 | Offset: 0x0ec | CallDoubleMethodV -> call_double_method_v
# Index:  60 | Offset: 0x0f0 | CallDoubleMethodA -> call_double_method_a
# Index:  61 | Offset: 0x0f4 | CallVoidMethod -> call_void_method
# Index:  62 | Offset: 0x0f8 | CallVoidMethodV -> call_void_method_v
# Index:  63 | Offset: 0x0fc | CallVoidMethodA -> call_void_method_a
# Index:  64 | Offset: 0x100 | CallNonvirtualObjectMethod -> call_nonvirtual_object_method
# Index:  65 | Offset: 0x104 | CallNonvirtualObjectMethodV -> call_nonvirtual_object_method_v
# Index:  66 | Offset: 0x108 | CallNonvirtualObjectMethodA -> call_nonvirtual_object_method_a
# Index:  67 | Offset: 0x10c | CallNonvirtualBooleanMethod -> call_nonvirtual_boolean_method
# Index:  68 | Offset: 0x110 | CallNonvirtualBooleanMethodV -> call_nonvirtual_boolean_method_v
# Index:  69 | Offset: 0x114 | CallNonvirtualBooleanMethodA -> call_nonvirtual_boolean_method_a
# Index:  70 | Offset: 0x118 | CallNonvirtualByteMethod -> call_nonvirtual_byte_method
# Index:  71 | Offset: 0x11c | CallNonvirtualByteMethodV -> call_nonvirtual_byte_method_v
# Index:  72 | Offset: 0x120 | CallNonvirtualByteMethodA -> call_nonvirtual_byte_method_a
# Index:  73 | Offset: 0x124 | CallNonvirtualCharMethod -> call_nonvirtual_char_method
# Index:  74 | Offset: 0x128 | CallNonvirtualCharMethodV -> call_nonvirtual_char_method_v
# Index:  75 | Offset: 0x12c | CallNonvirtualCharMethodA -> call_nonvirtual_char_method_a
# Index:  76 | Offset: 0x130 | CallNonvirtualShortMethod -> call_nonvirtual_short_method
# Index:  77 | Offset: 0x134 | CallNonvirtualShortMethodV -> call_nonvirtual_short_method_v
# Index:  78 | Offset: 0x138 | CallNonvirtualShortMethodA -> call_nonvirtual_short_method_a
# Index:  79 | Offset: 0x13c | CallNonvirtualIntMethod -> call_nonvirtual_int_method
# Index:  80 | Offset: 0x140 | CallNonvirtualIntMethodV -> call_nonvirtual_int_method_v
# Index:  81 | Offset: 0x144 | CallNonvirtualIntMethodA -> call_nonvirtual_int_method_a
# Index:  82 | Offset: 0x148 | CallNonvirtualLongMethod -> call_nonvirtual_long_method
# Index:  83 | Offset: 0x14c | CallNonvirtualLongMethodV -> call_nonvirtual_long_method_v
# Index:  84 | Offset: 0x150 | CallNonvirtualLongMethodA -> call_nonvirtual_long_method_a
# Index:  85 | Offset: 0x154 | CallNonvirtualFloatMethod -> call_nonvirtual_float_method
# Index:  86 | Offset: 0x158 | CallNonvirtualFloatMethodV -> call_nonvirtual_float_method_v
# Index:  87 | Offset: 0x15c | CallNonvirtualFloatMethodA -> call_nonvirtual_float_method_a
# Index:  88 | Offset: 0x160 | CallNonvirtualDoubleMethod -> call_nonvirtual_double_method
# Index:  89 | Offset: 0x164 | CallNonvirtualDoubleMethodV -> call_nonvirtual_double_method_v
# Index:  90 | Offset: 0x168 | CallNonvirtualDoubleMethodA -> call_nonvirtual_double_method_a
# Index:  91 | Offset: 0x16c | CallNonvirtualVoidMethod -> call_nonvirtual_void_method
# Index:  92 | Offset: 0x170 | CallNonvirtualVoidMethodV -> call_nonvirtual_void_method_v
# Index:  93 | Offset: 0x174 | CallNonvirtualVoidMethodA -> call_nonvirtual_void_method_a
# Index:  94 | Offset: 0x178 | GetFieldID -> get_field_id
# Index:  95 | Offset: 0x17c | GetObjectField -> get_object_field
# Index:  96 | Offset: 0x180 | GetBooleanField -> get_boolean_field
# Index:  97 | Offset: 0x184 | GetByteField -> get_byte_field
# Index:  98 | Offset: 0x188 | GetCharField -> get_char_field
# Index:  99 | Offset: 0x18c | GetShortField -> get_short_field
# Index: 100 | Offset: 0x190 | GetIntField -> get_int_field
# Index: 101 | Offset: 0x194 | GetLongField -> get_long_field
# Index: 102 | Offset: 0x198 | GetFloatField -> get_float_field
# Index: 103 | Offset: 0x19c | GetDoubleField -> get_double_field
# Index: 104 | Offset: 0x1a0 | SetObjectField -> set_object_field
# Index: 105 | Offset: 0x1a4 | SetBooleanField -> set_boolean_field
# Index: 106 | Offset: 0x1a8 | SetByteField -> set_byte_field
# Index: 107 | Offset: 0x1ac | SetCharField -> set_char_field
# Index: 108 | Offset: 0x1b0 | SetShortField -> set_short_field
# Index: 109 | Offset: 0x1b4 | SetIntField -> set_int_field
# Index: 110 | Offset: 0x1b8 | SetLongField -> set_long_field
# Index: 111 | Offset: 0x1bc | SetFloatField -> set_float_field
# Index: 112 | Offset: 0x1c0 | SetDoubleField -> set_double_field
# Index: 113 | Offset: 0x1c4 | GetStaticMethodID -> get_static_method_id
# Index: 114 | Offset: 0x1c8 | CallStaticObjectMethod -> call_static_object_method
# Index: 115 | Offset: 0x1cc | CallStaticObjectMethodV -> call_static_object_method_v
# Index: 116 | Offset: 0x1d0 | CallStaticObjectMethodA -> call_static_object_method_a
# Index: 117 | Offset: 0x1d4 | CallStaticBooleanMethod -> call_static_boolean_method
# Index: 118 | Offset: 0x1d8 | CallStaticBooleanMethodV -> call_static_boolean_method_v
# Index: 119 | Offset: 0x1dc | CallStaticBooleanMethodA -> call_static_boolean_method_a
# Index: 120 | Offset: 0x1e0 | CallStaticByteMethod -> call_static_byte_method
# Index: 121 | Offset: 0x1e4 | CallStaticByteMethodV -> call_static_byte_method_v
# Index: 122 | Offset: 0x1e8 | CallStaticByteMethodA -> call_static_byte_method_a
# Index: 123 | Offset: 0x1ec | CallStaticCharMethod -> call_static_char_method
# Index: 124 | Offset: 0x1f0 | CallStaticCharMethodV -> call_static_char_method_v
# Index: 125 | Offset: 0x1f4 | CallStaticCharMethodA -> call_static_char_method_a
# Index: 126 | Offset: 0x1f8 | CallStaticShortMethod -> call_static_short_method
# Index: 127 | Offset: 0x1fc | CallStaticShortMethodV -> call_static_short_method_v
# Index: 128 | Offset: 0x200 | CallStaticShortMethodA -> call_static_short_method_a
# Index: 129 | Offset: 0x204 | CallStaticIntMethod -> call_static_int_method
# Index: 130 | Offset: 0x208 | CallStaticIntMethodV -> call_static_int_method_v
# Index: 131 | Offset: 0x20c | CallStaticIntMethodA -> call_static_int_method_a
# Index: 132 | Offset: 0x210 | CallStaticLongMethod -> call_static_long_method
# Index: 133 | Offset: 0x214 | CallStaticLongMethodV -> call_static_long_method_v
# Index: 134 | Offset: 0x218 | CallStaticLongMethodA -> call_static_long_method_a
# Index: 135 | Offset: 0x21c | CallStaticFloatMethod -> call_static_float_method
# Index: 136 | Offset: 0x220 | CallStaticFloatMethodV -> call_static_float_method_v
# Index: 137 | Offset: 0x224 | CallStaticFloatMethodA -> call_static_float_method_a
# Index: 138 | Offset: 0x228 | CallStaticDoubleMethod -> call_static_double_method
# Index: 139 | Offset: 0x22c | CallStaticDoubleMethodV -> call_static_double_method_v
# Index: 140 | Offset: 0x230 | CallStaticDoubleMethodA -> call_static_double_method_a
# Index: 141 | Offset: 0x234 | CallStaticVoidMethod -> call_static_void_method
# Index: 142 | Offset: 0x238 | CallStaticVoidMethodV -> call_static_void_method_v
# Index: 143 | Offset: 0x23c | CallStaticVoidMethodA -> call_static_void_method_a
# Index: 144 | Offset: 0x240 | GetStaticFieldID -> get_static_field_id
# Index: 145 | Offset: 0x244 | GetStaticObjectField -> get_static_object_field
# Index: 146 | Offset: 0x248 | GetStaticBooleanField -> get_static_boolean_field
# Index: 147 | Offset: 0x24c | GetStaticByteField -> get_static_byte_field
# Index: 148 | Offset: 0x250 | GetStaticCharField -> get_static_char_field
# Index: 149 | Offset: 0x254 | GetStaticShortField -> get_static_short_field
# Index: 150 | Offset: 0x258 | GetStaticIntField -> get_static_int_field
# Index: 151 | Offset: 0x25c | GetStaticLongField -> get_static_long_field
# Index: 152 | Offset: 0x260 | GetStaticFloatField -> get_static_float_field
# Index: 153 | Offset: 0x264 | GetStaticDoubleField -> get_static_double_field
# Index: 154 | Offset: 0x268 | SetStaticObjectField -> set_static_object_field
# Index: 155 | Offset: 0x26c | SetStaticBooleanField -> set_static_boolean_field
# Index: 156 | Offset: 0x270 | SetStaticByteField -> set_static_byte_field
# Index: 157 | Offset: 0x274 | SetStaticCharField -> set_static_char_field
# Index: 158 | Offset: 0x278 | SetStaticShortField -> set_static_short_field
# Index: 159 | Offset: 0x27c | SetStaticIntField -> set_static_int_field
# Index: 160 | Offset: 0x280 | SetStaticLongField -> set_static_long_field
# Index: 161 | Offset: 0x284 | SetStaticFloatField -> set_static_float_field
# Index: 162 | Offset: 0x288 | SetStaticDoubleField -> set_static_double_field
# Index: 163 | Offset: 0x28c | NewString -> new_string
# Index: 164 | Offset: 0x290 | GetStringLength -> get_string_length
# Index: 165 | Offset: 0x294 | GetStringChars -> get_string_chars
# Index: 166 | Offset: 0x298 | ReleaseStringChars -> release_string_chars
# Index: 167 | Offset: 0x29c | NewStringUTF -> new_string_utf
# Index: 168 | Offset: 0x2a0 | GetStringUTFLength -> get_string_utf_length
# Index: 169 | Offset: 0x2a4 | GetStringUTFChars -> get_string_utf_chars
# Index: 170 | Offset: 0x2a8 | ReleaseStringUTFChars -> release_string_utf_chars
# Index: 171 | Offset: 0x2ac | GetArrayLength -> get_array_length
# Index: 172 | Offset: 0x2b0 | NewObjectArray -> new_object_array
# Index: 173 | Offset: 0x2b4 | GetObjectArrayElement -> get_object_array_element
# Index: 174 | Offset: 0x2b8 | SetObjectArrayElement -> set_object_array_element
# Index: 175 | Offset: 0x2bc | NewBooleanArray -> new_boolean_array
# Index: 176 | Offset: 0x2c0 | NewByteArray -> new_byte_array
# Index: 177 | Offset: 0x2c4 | NewCharArray -> new_char_array
# Index: 178 | Offset: 0x2c8 | NewShortArray -> new_short_array
# Index: 179 | Offset: 0x2cc | NewIntArray -> new_int_array
# Index: 180 | Offset: 0x2d0 | NewLongArray -> new_long_array
# Index: 181 | Offset: 0x2d4 | NewFloatArray -> new_float_array
# Index: 182 | Offset: 0x2d8 | NewDoubleArray -> new_double_array
# Index: 183 | Offset: 0x2dc | GetBooleanArrayElements -> get_boolean_array_elements
# Index: 184 | Offset: 0x2e0 | GetByteArrayElements -> get_byte_array_elements
# Index: 185 | Offset: 0x2e4 | GetCharArrayElements -> get_char_array_elements
# Index: 186 | Offset: 0x2e8 | GetShortArrayElements -> get_short_array_elements
# Index: 187 | Offset: 0x2ec | GetIntArrayElements -> get_int_array_elements
# Index: 188 | Offset: 0x2f0 | GetLongArrayElements -> get_long_array_elements
# Index: 189 | Offset: 0x2f4 | GetFloatArrayElements -> get_float_array_elements
# Index: 190 | Offset: 0x2f8 | GetDoubleArrayElements -> get_double_array_elements
# Index: 191 | Offset: 0x2fc | ReleaseBooleanArrayElements -> release_boolean_array_elements
# Index: 192 | Offset: 0x300 | ReleaseByteArrayElements -> release_byte_array_elements
# Index: 193 | Offset: 0x304 | ReleaseCharArrayElements -> release_char_array_elements
# Index: 194 | Offset: 0x308 | ReleaseShortArrayElements -> release_short_array_elements
# Index: 195 | Offset: 0x30c | ReleaseIntArrayElements -> release_int_array_elements
# Index: 196 | Offset: 0x310 | ReleaseLongArrayElements -> release_long_array_elements
# Index: 197 | Offset: 0x314 | ReleaseFloatArrayElements -> release_float_array_elements
# Index: 198 | Offset: 0x318 | ReleaseDoubleArrayElements -> release_double_array_elements
# Index: 199 | Offset: 0x31c | GetBooleanArrayRegion -> get_boolean_array_region
# Index: 200 | Offset: 0x320 | GetByteArrayRegion -> get_byte_array_region
# Index: 201 | Offset: 0x324 | GetCharArrayRegion -> get_char_array_region
# Index: 202 | Offset: 0x328 | GetShortArrayRegion -> get_short_array_region
# Index: 203 | Offset: 0x32c | GetIntArrayRegion -> get_int_array_region
# Index: 204 | Offset: 0x330 | GetLongArrayRegion -> get_long_array_region
# Index: 205 | Offset: 0x334 | GetFloatArrayRegion -> get_float_array_region
# Index: 206 | Offset: 0x338 | GetDoubleArrayRegion -> get_double_array_region
# Index: 207 | Offset: 0x33c | SetBooleanArrayRegion -> set_boolean_array_region
# Index: 208 | Offset: 0x340 | SetByteArrayRegion -> set_byte_array_region
# Index: 209 | Offset: 0x344 | SetCharArrayRegion -> set_char_array_region
# Index: 210 | Offset: 0x348 | SetShortArrayRegion -> set_short_array_region
# Index: 211 | Offset: 0x34c | SetIntArrayRegion -> set_int_array_region
# Index: 212 | Offset: 0x350 | SetLongArrayRegion -> set_long_array_region
# Index: 213 | Offset: 0x354 | SetFloatArrayRegion -> set_float_array_region
# Index: 214 | Offset: 0x358 | SetDoubleArrayRegion -> set_double_array_region
# Index: 215 | Offset: 0x35c | RegisterNatives -> register_natives
# Index: 216 | Offset: 0x360 | UnregisterNatives -> unregister_natives
# Index: 217 | Offset: 0x364 | MonitorEnter -> monitor_enter
# Index: 218 | Offset: 0x368 | MonitorExit -> monitor_exit
# Index: 219 | Offset: 0x36c | GetJavaVM -> get_java_vm
# Index: 220 | Offset: 0x370 | GetStringRegion -> get_string_region
# Index: 221 | Offset: 0x374 | GetStringUTFRegion -> get_string_utf_region
# Index: 222 | Offset: 0x378 | GetPrimitiveArrayCritical -> get_primitive_array_critical
# Index: 223 | Offset: 0x37c | ReleasePrimitiveArrayCritical -> release_primitive_array_critical
# Index: 224 | Offset: 0x380 | GetStringCritical -> get_string_critical
# Index: 225 | Offset: 0x384 | ReleaseStringCritical -> release_string_critical
# Index: 226 | Offset: 0x388 | NewWeakGlobalRef -> new_weak_global_ref
# Index: 227 | Offset: 0x38c | DeleteWeakGlobalRef -> delete_weak_global_ref
# Index: 228 | Offset: 0x390 | ExceptionCheck -> exception_check
# Index: 229 | Offset: 0x394 | NewDirectByteBuffer -> new_direct_byte_buffer
# Index: 230 | Offset: 0x398 | GetDirectBufferAddress -> get_direct_buffer_address
# Index: 231 | Offset: 0x39c | GetDirectBufferCapacity -> get_direct_buffer_capacity
# Index: 232 | Offset: 0x3a0 | GetObjectRefType -> get_object_ref_type