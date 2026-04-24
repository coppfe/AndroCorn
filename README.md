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
    <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python">
  </a>
  <a href="https://github.com/coppfe/AndroCorn/network/members">
    <img src="https://img.shields.io/github/forks/coppfe/AndroCorn?style=for-the-badge&color=lightgrey" alt="Forks">
  </a>
</p>

# 🦄 AndroCorn
**A High-Fidelity, Android Native Emulator for Research and Reverse Engineering.**

---

## 🚀 Overview
**AndroCorn** is a sophisticated Android Emulation framework powered by the Unicorn Engine, designed for high-fidelity native library analysis. Unlike basic wrappers, AndroCorn focuses on bypassing modern anti-analysis techniques and providing a complete system environment.
Key Features:

* Architecture Support: Full ARM32 (v7-a) and ARM64 (v8-a) execution.

* Advanced Memory Introspection: First-class support for process_vm_readv and vectorized I/O, enabling bypasses for self-integrity checks and inline-hook detection.

* System Register Magic: Implements a custom ASM-based mechanism to read/write ARM System Registers (CP15/SysRegs) — overcoming a major native Unicorn limitation.

* Bionic-Compliant TLS: Meticulous emulation of Android's Bionic TLS slots and offsets, allowing libc and libc++ to initialize their own internal structures naturally.

* Smarter Pythonic Linker: A fully custom linker implemented in Python that supports modern Android relocation types and complex dependency resolution.

* Isolated VFS: A completely sandboxed Virtual File System with support for:

    - Virtual Devices: /dev/urandom, /dev/null, /dev/zero with correct major/minor IDs and st_mode.

    - ProcFS Emulation: Dynamic generation of /proc/self/maps and /proc/self/status to satisfy anti-debug scans.

* JNI & Java Bridge: Seamlessly interact with native code using a JNI layer and Java-like classes implemented entirely in Python.

* Security & Life-cycle: Experimental fork() and execve() support, primitive Copy-On-Write (CoW) memory optimization, and Yama ptrace scope integration.

* Reverse Engineering Ready: * Automatic symbol demangling ([cpp_demangle](https://github.com/gimli-rs/cpp_demangle)).

    - Unmapped QEMU register manipulation via ASM code generation.

    - Integration with Ghidra and custom native tools.
    
It is designed for security researchers, malware analysts, and developers who need to run complex Android NDK binaries (like TikTok Metasec, game engines, or obfuscated protectors) with surgical accuracy.

## ✨ Key Improvements over AndroidNativeEmu

### 🏗️ Dynamic Linker
AndroCorn features a rewritten **Linker Engine** that follows modern Bionic (Android libc) specifications more closely. 
* **Enhanced Relocation Handling:** Smarter patching of GOT/PLT entries.
* **Improved Dependency Resolution:** Better management of complex `.so` dependency trees.

### 🧵 Advanced TLS & DTV Management
We introduced a robust **DTV (Dynamic Thread Vector) Builder** logic for both ARM32 and ARM64. 
* Full support for `thread_local` storage.
* Seamless handling of `pthread` lifecycle, including `futex` synchronization and thread-specific data.
* Verified compatibility with `libc++_shared` internals.

### 🔍 Debugging & Type Safety
* **Strict Typing:** Heavily refactored codebase using Python type hinting for better IDE support and fewer runtime bugs.
* **Deep Trace Logging:** Granular logging of syscalls, memory mappings, and linker phases.
* **Symbolic Hooks:** More intuitive API for hooking and intercepting native functions.

### 👀 Read & Write System Registers
* Emulator supporting some unicorn unmapped registers by asm code execution.

---

## 🛠️ Getting Started

### Installation
```bash
git clone https://github.com/coppfe/AndroCorn.git
cd AndroCorn
pip install -r requirements.txt
```

## Quick Usage
```python
from androidemu.emulator import Emulator
from androidemu.const import emu_const

# Initialize AndroCorn
emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32, muti_task=True)

# Load your library with the next-gen linker
libc = emulator.load_library("vfs/system/lib/libc.so", do_init=True)
print("[*] AndroCorn is ready.")
```

## 🤝 Contribution

AndroCorn is an open-source project. If you find a bug in the linker or want to improve the syscall emulation, feel free to submit a Pull Request!

---

## ⚖️ License & Credits

AndroCorn inspired of [ExAndroidNativeEmu](https://github.com/maiyao1988/ExAndroidNativeEmu) (by maiyao1988) and [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu) (by AeonLucid). Thanks for their work ❤️

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License as published by the Free Software Foundation, either version 3 of the License.**

- License: [GNU GPL v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

###### Probably not a very original name for the project, but okay.