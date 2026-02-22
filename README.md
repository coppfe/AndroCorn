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
**AndroCorn** is a sophisticated fork of [ExAndroidNativeEmu](https://github.com/maiyao1988/ExAndroidNativeEmu), rebuilt for precision and stability. While the original provided the foundation, AndroCorn evolves the ecosystem by introducing a strictly typed architecture, advanced debugging capabilities, and a completely overhauled dynamic linker.

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

AndroCorn is a fork of [ExAndroidNativeEmu](https://github.com/maiyao1988/ExAndroidNativeEmu) (by maiyao1988) and [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu) (by AeonLucid).

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License as published by the Free Software Foundation, either version 3 of the License.**

- Original Project: [AeonLucid/AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu)
- License: [GNU GPL v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

###### Probably not a very original name for the project, but okay.
