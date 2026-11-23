<!-- Top -->
<p align="center">
  <img src="assets/androcorn.png" alt="AndroCorn Cover" width="80%">
</p>

<p align="center">
  <a href="https://github.com/coppfe/AndroCorn/stargazers">
    <img src="https://img.shields.io/github/stars/coppfe/AndroCorn?style=for-the-badge&color=yellow" alt="Stars">
  </a>
  <a href="https://github.com/coppfe/AndroCorn/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/coppfe/AndroCorn?style=for-the-badge&color=blue" alt="License">
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python">
  </a>
  <a href="https://github.com/coppfe/AndroCorn/network/members">
    <img src="https://img.shields.io/github/forks/coppfe/AndroCorn?style=for-the-badge&color=lightgrey" alt="Forks">
  </a>
  <a href="https://coppfe.github.io/AndroCorn/">
    <img src="https://img.shields.io/badge/docs-GitHub%20Pages-green?style=for-the-badge&logo=github" alt="Docs">
  </a>
</p>

# 🦄 AndroCorn
A lightweight, scriptable Android user-mode emulator based on Unicorn Engine.

This project is built for **reverse engineering, dynamic analysis, and security research** on Android native libraries (`.so`) without running a heavy full-system Android emulator or physical device.

---

### What it does

Instead of booting a full Android OS, `androidemu` runs isolated native ARM/ARM64 code in user-mode by providing:

- **Custom Linker & ELF Loader**: Loads Android `.so` dependencies with support for custom memory mapping (`MemoryMap`), TLS/DTV, and Bionic runtime structures (including 64-bit linker support).
- **CPU & Architecture Support**: ARM32 and ARM64 execution with mapping for general-purpose, FP, and SIMD registers (`Q0-Q7`, `D0-D7`).
- **Kernel Emulation**: Handles common Linux syscalls, virtual filesystem (VFS) bindings, threads/scheduler, and basic `/proc` emulation.
- **JNI & Java Environment**: Built-in mock Java Virtual Machine (JVM) and JNI environment capable of handling reflection, class inheritance, signature resolution, exceptions, and core Android API stubs (`PackageManager`, `Binder`, `Context`, Crypto, etc.).

---

### Advanced Tooling & Instrumentation Notice

`androidemu` focuses strictly on the core execution environment, memory management, and JNI bridges. 

All heavy instrumentation subsystems (such as memory watchpoints, instruction fuel tracing, and taint tracking) have been moved out of `HookManager` to keep the runtime minimal.

For advanced analysis, tracing, and hook engines, see:
👉 **[androcorn_native_tools](https://github.com/coppfe/androcorn_native_tools)**
---

### Quick Start

#### Requirements
- Python 3.10+
- Unicorn Engine bindings

#### Basic Usage

```python
import logging
from androidemu.core.emulator import Emulator
from androidemu.const import emu_const

logging.basicConfig(level=logging.INFO)

# Initialize ARM64 emulator with virtual filesystem
emu = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM64)

# Load target library
lib = emu.load_library("vfs/system/lib64/libtarget.so")

# Call an exported native function
# e.g., JNI_OnLoad(JavaVM *vm, void *reserved)
res = emu.call_symbol(lib, "JNI_OnLoad", emu.java_vm.address_ptr, 0)
print(f"JNI_OnLoad returned: {res}")
```

---

## Tests
Run tests:
```bash
pytest tests
```