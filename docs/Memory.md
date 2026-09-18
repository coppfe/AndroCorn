# Memory Subsystem & Architecture Layout

AndroCorn v2.0 introduces a strictly deterministic virtual memory layout. Internal runtime metadata is completely segregated from user-space allocations to prevent heap collision and anti-tamper heuristics.

---

## Memory Map Specification

All core boundaries are defined in `androidemu/data/layout.py`.

| Domain | Virtual Address Range | Size | Description |
| :--- | :--- | :--- | :--- |
| **`ASM_CODE`** | `0x00001000 - 0x00002000` | 4 KB | Scratchpad page used by `CPU_Utils` for executing ARM helper snippets. |
| **`BRIDGES`** | `0x01000000 - 0x01200000` | 2 MB | Dynamic callback trampolines connecting Python hooks with Unicorn. |
| **`HOOK_STUB`** | `0x01200000 - 0x01300000` | 1 MB | JNI bridge function table pointers. |
| **`TLS / DTV`** | `0x02000000 - 0x02010000` | 64 KB | Static thread-local storage, DTV table, and pthread structures. |
| **`STOP_MEMORY`** | `0x03000000 - 0x03002000` | 8 KB | Return trap endpoints (`SIGRET = 0x03001000`). |
| **`MAIN STACK`** | `0x10000000 - 0x10800000` | 8 MB | Main execution thread stack. |
| **`CHILD STACK`**| `0x11000000 - ...` | Variable | Base search boundary for sub-task and worker thread stacks. |
| **`SOINFO`** | `0x20000000 - 0x21000000` | 16 MB | Bionic Dynamic Linker metadata linked list (`solist`). |
| **`MODULES`** | `0x40000000 - ...` | Variable | Dynamic library load addresses (`libc.so`, native binaries). |
| **`EMU_HEAP`** | `0x60000000 - 0x68000000` | 128 MB | Internal emulator memory allocator (`static_alloc`, `dynamic_alloc`). |
| **`BRK / [heap]`**| `0x70000000 - 0x70800000` | 8 MB | Deterministic Linux process heap managed strictly by `sys_brk`. |
| **`MMAP_BASE`** | `0x80000000 - 0xA0000000` | 512 MB | Dynamic anonymous allocations (`mmap`, `mmap2`). |
| **`APP_PROCESS`**| `0xAB000000 - ...` | Variable | Mapped `/system/bin/app_process` node. |
| **`LINKER`** | `0xB6F00000 - ...` | Variable | Mapped dynamic linker image. |
| **`JVM IDS`** | `0xD2000000 - ...` | Variable | Virtual pointer IDs for Java methods and fields. |

> **Anti-Detection Hiding**: The regions `ASM_CODE`, `BRIDGES`, `TLS`, `SOINFO`, `STOP_MEMORY`, `EMU_HEAP`, and `JVM IDS` are automatically excluded from `/proc/self/maps`.

---

## Memory Forensic & Debugging Tools

The `androidemu.utils.memory.helpers` module provides low-level debugging utilities.

### 1. Hexdump
```python
from androidemu.utils.memory.helpers import hexdump

# Dumps formatted hex with ASCII preview
print(hexdump(emu.mu, address=0x70000000, size=64))
```

## 2. Telescope (Pointer Chain Resolver)

Recursively dereferences addresses on the stack or heap, resolving pointers to module names, symbols, or strings (pwndbg / GEF style):

```python
from androidemu.utils.memory.helpers import telescope

print(telescope(emu, address=emu.registers.v_sp, depth=8))
# Output:
# 107ff000: 4014b120 -> 40150240 (libnative.so: secret_key) -> "P@ssw0rd123"
```

## 3. Automatic String Decoding

Automatically detects whether memory contains UTF-8 or UTF-16LE without crashing:

```python
from androidemu.utils.memory.helpers import read_string_auto

text = read_string_auto(emu.mu, str_ptr)
```
## Snapshots & Memory Rollback

You can capture the full state of the CPU and all writable memory pages to perform fast, repetitive native function executions (e.g. fuzzing or brute-forcing tokens):

```python
# 1. Take a baseline snapshot
snapshot = emu.memory.create_snapshot(emu)

for payload in test_payloads:
    # 2. Execute target function
    res = emu.call_symbol(my_module, "process_data", payload)
    
    # 3. Instantly revert CPU and RW memory pages back to pristine state
    emu.memory.restore_snapshot(emu, snapshot)
```

