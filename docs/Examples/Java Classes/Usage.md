I'm nothing literally changed here when was updating ExAndroidNativeEmu, so here is full old code-style.

Remember, the first arg for java methods was emulator object!!!

Always pass args_list for correct type cast.

## Example of init class:

For the first example i will show you an TikTok Old Security Layer.
Here we making a simple backward compability with the binary

```python
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.array import ByteArray
from androidemu.java.jni_ref import jobject
from androidemu.java.classes.list import List

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
    
    ... # full implementation in tests/test_native.py
```

Now, we need to add this class to our environment:

```python
def init():
    emulator = Emulator(vfs_root="vfs", arch=1) # 1 = ARM32 by Unicorn Mappings (and my mappings too lol)
    
    emulator.java_classloader.add_class(com_ss_sys_ces_a)
    emulator.java_classloader.add_class(java_lang_Thread)
```

And... Yes this all. Classloader will make a jni link and other dirty work.

## Warning!
Emulator cannot make auto-cast pytypes for java classes. If your java class was return an object, then you need to return a java object. 
Example was like here:

```python
@staticmethod
    @java_method_def(name='njss', args_list=["jint", "jobject"], signature='(ILjava/lang/Object;)Ljava/lang/Object;', native=False)
    def njss(emu, i1, s):
        # just stub it idk what this shit want. if you want to check reverse older versions of tiktok (overland) like <20.x.x
        if i1 == 136:
            return ByteArray([])
        elif i1 == 235:
            pass
```

as you can see -> when i1 is equal to some magic value i return a java wrapper.

Java Types like jbyteArray, jintArray, jobjectArray -> is a jobject heirs, so just write jobject for correct cast

## Mention!
```python
@staticmethod
```
is not required. It's just for java-style code! See how it works in section Java, file Java Method Definer

If you want more examples you can check the `java/classes` dir.