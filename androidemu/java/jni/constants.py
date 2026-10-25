JNI_FALSE = 0
JNI_TRUE = 1

JNI_VERSION_1_1 = 0x00010001
JNI_VERSION_1_2 = 0x00010002
JNI_VERSION_1_4 = 0x00010004
JNI_VERSION_1_6 = 0x00010006

JNI_OK = 0                  # no error
JNI_ERR = -1                # generic error
JNI_EDETACHED = -2          # thread detached from the VM
JNI_EVERSION = -3           # JNI version error
JNI_ENOMEM = -4             # Out of memory
JNI_EEXIST = -5             # VM already created
JNI_EINVAL = -6             # Invalid argument

JNI_COMMIT = 1              # copy content, do not free buffer
JNI_ABORT = 2               # free buffer w/o copying back

JNI_InvalidRefType = 0      # invalid ref type
JNI_LocalRefType = 1        # local ref
JNI_GlobalRefType = 2       # global ref
JNI_WeakGlobalRefType = 3   # weak global ref

# Primitive arrays (everything but byte[], which keeps its bytearray code):
# JNI type letter -> (struct format to read a native element, format to write it, bytes per element)
JNI_PRIM_ELEMENT = {
    "Z": ("B", "B", 1), "C": ("H", "H", 2), "S": ("h", "H", 2), "I": ("i", "I", 4),
    "J": ("q", "Q", 8), "F": ("f", "f", 4), "D": ("d", "d", 8),
}
JNI_PRIM_NAME = {"Z": "Boolean", "C": "Char", "S": "Short", "I": "Int", "J": "Long", "F": "Float", "D": "Double"}

# JNI return kinds that are not returned like an int: jlong, jfloat, jdouble (see wide_or_fp_return)
JNI_WIDE_OR_FP_KINDS = ("J", "F", "D")