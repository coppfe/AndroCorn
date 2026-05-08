Use this method when you want to hook some address. Here is example how to hook by symbol name
Probably, this work only for a direct calls, like fork, exit, etc. Remember it when you will start writing your own hooks.

## Runtime hook example
```python
from androidemu.emulator import Emulator
import logging
from androidemu.const.emu_const import ARCH_ARM32, ARCH_ARM64

def exit(emu, *argv):
    print("exit called", *argv)
    return 0

logging.basicConfig(level=logging.DEBUG)

def main():
    emu = Emulator(arch=ARCH_ARM64, init_sys_libs=False)
    libcm = emu.load_library("libc.so", main_lib=True)

    exit_addr = emu.linker.find_function_by_name("exit")
    emu.address_hooker.fun_hook(exit_addr, 1, exit, cb_after=None)
    emu.call_symbol(libcm, 'exit', 45325)

if __name__ == "__main__":
    main()
```

Also if you know an address of function, you can hook it like this:

## Rintime address hook example
```python
from androidemu.emulator import Emulator
import logging
from androidemu.const.emu_const import ARCH_ARM32, ARCH_ARM64

def exit(emu, *argv):
    print("exit called", *argv)
    return 0

logging.basicConfig(level=logging.DEBUG)

def main():
    emu = Emulator(arch=ARCH_ARM32, init_sys_libs=False)
    libcm = emu.load_library("libc.so", main_lib=True)

    exit_addr = 0x400163f1
    emu.address_hooker.fun_hook(exit_addr, 1, exit, cb_after=None)
    emu.call_symbol(libcm, 'exit', 45325)
if __name__ == "__main__":
    main()
```

## Warning!
I'm not recommend this method bcs this examples is hooking address **after** full init of lib. Some hooks will not work like `malloc` in libc with this method.
So im recommend use the API Method.