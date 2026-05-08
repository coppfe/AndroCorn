API Hooks are always initializing by preload module (init_hooks). However, init hooks was maded to stub any symbol BEFORE relocations.
So, if your case is full custom implement logic of function -> you need initialize a stub address hook method.

It's just change the func logic to bx lr or ret (arch based)

All hooks that using API need add to init hooks classes list. In the top of python file you will find out 2 const vars.
Also, all hooks was inheritance their own ABS Class, where all classes was obligied to path global hooks dict.

Symbol Hooks (stub_addr) was always using decorator native_method because... ? No really why like... ok
Func Hooks (hook_addr) was not using decorator. AddressHooker (old name is FuncHooker) pass a Emulator object as first argument

## API Function (aka hook_addr) Hook example
```python
from androidemu.native.hook.base import HookAddress

logger = logging.getLogger(__name__)

class LibCFunHooks(HookAddress):

    def __init__(self):
        super().__init__()
        
        self._func_table = [
            ("__libc_write_log", 2, self.libc_log, None)
        ] # name, num_args, before, after

        for hook in self._func_table:
            self.global_func_table.append(hook)
    
    def libc_log(self, emu, *argv):
        print("Triggered!")
```

### Example for Emulator with HookAddress
```python
from androidemu.emulator import Emulator
from androidemu.native.hook.base import HookAddress

class LibCFunHooks(HookAddress):

    def __init__(self):
        super().__init__()
        
        self._func_table = [
            ("malloc", 1, self.hook_malloc, None)
        ] # (sym_name, num_args, callback_before, callback_after)

        for hook in self._func_table:
            self.global_func_table.append(hook)
    
    def hook_malloc(self, emu, size):
        if size > 128:
            print(f"[*] Malloc: {size}")

def init():
    LibCFunHooks() # <- Updating global hooks table.
    emulator = Emulator(vfs_root="vfs", muti_task=True, arch=1, init_sys_libs=True)
    ...
```

# API Symbol (aka stub_addr) Hook Example
```python
from androidemu.native.stub.base import StubAddress

class LibCSymbolHooks(StubAddress):

    def __init__(self):
        super().__init__()
        
        self._func_table = {
            "__stack_chk_fail": self.stack_check_fail
        }
        self.global_func_table.update(self._func_table)
        
    @native_method # <- Symbol Hooks working as natives so here is the first arg is Unicorn Object.
    def stack_check_fail(self, uc):
        raise RuntimeError("__stack_chk_fail called!!!")
```

As you can see, all methods there was inheritance base abstract class.

## Example with Emulator object for stubbing addresses
```python
from androidemu.java.helpers.native_method import native_method

class LibCStubs:

    def __init__(self, emu: 'Emulator'):
        super().__init__()
        
        self._emu = emu

        self._func_table = {"malloc": self.hook_malloc}

        for key, hook in self._func_table.items():
            self._emu.linker.add_symbol_hook(key, self._emu._hooker.write_function(hook))
    
    @native_method
    def hook_malloc(self, uc, size):
        print(f"[*] Malloc: {size}")

def init():
    emulator = Emulator(vfs_root="vfs", muti_task=True, arch=1, init_sys_libs=False) # <- Toggle init_sys_libs to false to have time for hook
    LibCStubs(emulator)
```

Or like this one:

```python
from androidemu.java.helpers.native_method import native_method
from androidemu.native.stub.base import StubAddress

class LibCStubs(StubAddress):

    def __init__(self, emu: 'Emulator'):
        super().__init__()
        
        self._emu = emu

        self._func_table = {"malloc": self.hook_malloc}

        for key, hook in self._func_table.items():
            self.global_func_table[key] = hook
    
    @native_method
    def hook_malloc(self, uc, size):
        print(f"[*] Malloc: {size}")

def init():
    emulator = Emulator(vfs_root="vfs", muti_task=True, arch=1, init_sys_libs=False) # <- Toggle init_sys_libs to false to have time for hook
    LibCStubs(emulator)
    emulator.hooks.init_stubs()
```

# Warning!
`super().__init__` is required to update global table!