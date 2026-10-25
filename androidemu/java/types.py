"""
Java types, primitives and type-hint facades.
Provides IDE autocompletion without runtime overhead or circular imports.
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Any, Union

# =========================================================================
# 1. JAVA PRIMITIVE TYPE ALIASES (для чистого кода и IDE)
# =========================================================================
jboolean = bool
jbyte = int
jchar = int
jshort = int
jint = int
jlong = int
jfloat = float
jdouble = float
jvoid = None

# =========================================================================
# 2. CORE JAVA OBJECTS (TYPE_CHECKING facade)
# =========================================================================
if TYPE_CHECKING:
    from .classes.java.lang.object import Object as JObject
    from .classes.java.lang.clazz import Class as JClass
    from .classes.java.lang.string import String as JString
    from .classes.java.lang.throwable import Throwable as JThrowable
    from .classes.java.lang.array import (
        Array as JArray,
        ByteArray as JByteArray,
        IntArray as JIntArray,
        StringArray as JStringArray,
        ObjectArray as JObjectArray,
    )
    from .classes.java.util.list import List as JList, ArrayList as JArrayList
    from .classes.java.util.map import HashMap as JHashMap
else:
    JObject = object
    JClass = object
    JString = object
    JThrowable = Exception
    JArray = object
    JByteArray = object
    JIntArray = object
    JStringArray = object
    JObjectArray = object
    JList = object
    JArrayList = object
    JHashMap = object

def is_java_instance(obj: Any, jvm_name: str) -> bool:
    if obj is None or obj == 0:
        return False
    
    cls = getattr(obj, '__class__', None)
    while cls is not None:
        if getattr(cls, 'jvm_name', None) == jvm_name:
            return True
        cls = getattr(cls, 'jvm_super', None)
    return False