# Native Symbol Hooking & Tracing

AndroCorn v2.0 features a unified, modular `HookManager` (`emu.hook_manager`).

---

## Hook Types Matrix

| Mechanism | Method | Performance | Target Scope |
| :--- | :--- | :--- | :--- |
| **Linker Stub** | `emu.hook_manager.stub()` | Fast | Intercepts imported functions in other modules via GOT/PLT. |
| **Inline Hook** | `emu.hook_manager.inline()` | Medium | Intercepts function prologues/epilogues by virtual address. |
| **Memory Watchpoint** | `emu.hook_manager.watch()` | High Overhead | Monitors memory read/write operations with caller context. |
| **Cross-Module Tracer** | `CrossModuleTracer` | Fast (Block-level)| Traces function calls between `.so` module boundaries. |

---

## 1. Linker Symbol Hooking (`stub`)

Injects hooks into external cross-module calls via relocation tables. Must be registered **before** loading target libraries:

```python
from androidemu import Emulator
from androidemu.native.helpers.method import native_method

@native_method
def hook_kill(emu, pid, sig):
    print(f"[Stub] Intercepted kill({pid}, {sig})")
    return 0

emu = Emulator(init_sys_libs=False)
emu.hook_manager.stub("kill", hook_kill)

libcm = emu.load_library("libc.so")
```

## 2. Inline Code Hooking (inline)

Intercepts execution at any virtual address. Allows argument modification and early returns:

```python
emu = Emulator(init_sys_libs=False)
libcm = emu.load_library("libc.so")
malloc_addr = libcm.find_symbol("malloc")

def on_malloc_before(emu, size):
    print(f"[malloc] Allocating {size} bytes")
    # Return (True, custom_value) to bypass original code execution
    return False 

def on_malloc_after(emu, ret_addr, size):
    print(f"[malloc] Returned address: 0x{ret_addr:X}")
    return ret_addr

emu.hook_manager.inline(
    addr=malloc_addr,
    num_args=1,
    cb_before=on_malloc_before,
    cb_after=on_malloc_after
)
```
## 3. Memory Watchpoints (watch)

Monitors reads and writes to sensitive memory zones (AES keys, decrypted payloads, anti-debug flags) and logs the calling instruction and module:

```python
def on_key_read(emu, pc, addr, size):
    print(f"[KEY READ] Address 0x{addr:X} read by PC=0x{pc:X}")

def on_key_write(emu, pc, addr, size, value):
    print(f"[KEY WRITE] Address 0x{addr:X} written with 0x{value:X} by PC=0x{pc:X}")

# Watch 32 bytes of cryptographic key buffer
emu.hook_manager.watch(
    addr=0x70001500,
    size=32,
    tag="AES_KEY",
    on_read=on_key_read,
    on_write=on_key_write
)
```

## 4. Cross-Module Execution Tracer

Traces inter-module jumps (e.g. from an obfuscated library into libc.so) without the massive overhead of instruction-by-instruction logging:

```python
from androidemu.native.hook.hooks.tracer import CrossModuleTracer

tracer = CrossModuleTracer(emu)
tracer.start()

# Native library execution triggers warnings when crossing module boundaries:
# [JUMP] libnative.so -> libc.so: malloc (LR: 0x40021a40)
# [JUMP] libc.so -> libnative.so+0x1a44 (LR: 0x40021a40)

emu.call_symbol(my_module, "verify_integrity")
tracer.stop()
```