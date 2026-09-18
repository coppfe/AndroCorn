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
  <a href="https://coppfe.github.io/AndroCorn/">
    <img src="https://img.shields.io/badge/docs-GitHub%20Pages-green?style=for-the-badge&logo=github" alt="Docs">
  </a>
</p>

# 🦄 AndroCorn
**Lightweight, scriptable Android user-space emulator for reverse engineering and security research.**

---

## 🚀 Overview

**AndroCorn** is an isolated Android user-space emulator built on top of the [Unicorn Engine](https://www.unicorn-engine.org/).

It allows security researchers and reverse engineers to run, inspect, and fuzz native shared libraries (`.so`) across **ARM32 (ARMv7-A)** and **ARM64 (AArch64)** architectures on Linux, macOS, and Windows without running bulky Android Virtual Devices (AVD) or requiring physical hardware.

---

## ✨ Key Features

* **True Dual-Architecture Support**: Native support for ARM32 and ARM64. Architecture switching requires only a single parameter change, complete with Thumb mode, VFP/NEON, and hardware-accurate struct packing.
* **Streamlined Calling Convention & Register Mapping (`v_*`)**: Read and write CPU registers directly using virtual properties (`v_pc`, `v_sp`, `v_ret`, `v_reg_0..30`). Function calls automatically push excess parameters onto the stack with proper 16-byte alignment.
* **Stateless Kernel Syscall Engine**: Uniform syscall handling passing a single `emu` context instance. Fully handles file descriptors, network sockets, multithreading (`clone`, `futex`), signals, and `/proc/self/maps` reflection.
* **Bypass Anti-Emulation Checks**: Object-oriented Virtual File System (`VFSManager` / `VfsNode`) providing virtual character devices (`/dev/urandom`, `/dev/binder`, `/dev/ptmx`), dynamic `/system/bin/am get-config` evaluation, SELinux `xattr` labeling, and linker `__dl__ZL6solist` resolution.
* **Modern Reversing Tools**: Inline function hooking, memory read/write watchpoints with caller frame resolution, cross-module execution tracing, and instant memory snapshots for fuzzing.

---

## 📦 Installation

Clone the repository and install it in editable mode:

```bash
git clone https://github.com/coppfe/AndroCorn.git
cd AndroCorn
pip install -r requirements.txt
pip install -e .
```

## 💡 Practical Examples

### 1. Basic Initialization & Native Function Execution
```python
from androidemu import Emulator, ARCH_ARM64

# Initialize ARM64 emulator pointing to virtual filesystem directory
emu = Emulator(vfs_root="vfs", arch=ARCH_ARM64)

# Load target shared library (resolves dependencies and runs init_array)
lib = emu.load_library("libnative.so", do_init=True)

# Call an exported native symbol with arguments
result = emu.call_symbol(lib, "calculate_token", 1337, "secret_salt")
print(f"[+] Output: {result:#x}")
```

### 2. Direct Register Manipulation via Virtual ABI (v_*)

Access registers cleanly without boilerplate dictionary Lookups:

```python
regs = emu.registers

# Reading CPU state
current_pc = regs.v_pc
stack_ptr  = regs.v_sp
arg0       = regs.v_reg_0

# Writing CPU state
regs.v_reg_0 = 0x1337
regs.v_ret   = 0

# Controlling Thumb state (ARM32)
if regs.is_thumb():
    regs.clear_thumb()
```

### 3. Hooking: Linker Stub vs Inline Hook
```python
# 1. Stub external imports before dependent libraries are loaded
def fake_getpid(emu):
    return 1000

emu.hook_manager.stub("getpid", fake_getpid)

# 2. Hook internal function by virtual address
lib = emu.load_library("libtarget.so")
target_addr = lib.find_symbol("crypto_verify")

def on_crypto_before(emu, key_ptr, size):
    print(f"[!] crypto_verify called with size={size}")
    # Return (True, custom_value) to skip original code execution
    return True, 1

emu.hook_manager.inline(target_addr, num_args=2, cb_before=on_crypto_before)
```

### 4. Memory Watchpoints with Caller Inspection

Monitor reads and writes to sensitive memory buffers (keys, decrypted blobs, anti-debug flags) and identify the calling instruction and module:

```python
def on_key_read(emu, pc, addr, size):
    print(f"[WATCH:READ] Key accessed at {addr:#x} by PC={pc:#x}")

def on_key_write(emu, pc, addr, size, value):
    print(f"[WATCH:WRITE] Key modified at {addr:#x} -> {value:#x}")

# Set watchpoint over 32 bytes of cryptographic key storage
emu.hook_manager.watch(
    addr=0x70001500,
    size=32,
    tag="AES_KEY",
    on_read=on_key_read,
    on_write=on_key_write
)
```

### 5. Memory Snapshots & State Rollback

Capture the state of the CPU and all writable memory pages to perform fast, repetitive native function executions without restarting the emulator:

```python
lib = emu.load_library("libcrypto.so")
verify_func = lib.find_symbol("check_signature")

# 1. Take a baseline memory snapshot
snapshot = emu.memory.create_snapshot(emu)

for payload in candidate_payloads:
    # 2. Call target routine
    result = emu.call_native(verify_func, payload)
    
    # 3. Instantly revert CPU registers, stack, and heap back to pristine state
    emu.memory.restore_snapshot(emu, snapshot)

```

### 6. File System Mapping & Anti-Tamper Bypass
```python
# Mount host APK to virtual path expected by target library
vf = emu.vfs.mount_file(
    virt_path="/data/app/com.target.app/base.apk",
    host_path="tests/bin/clean_base.apk",
    uid=1000
)

# Protect against integrity checkers that verify memory maps via /proc/self/maps:
emu.memory.map(
    0,
    size=vf.get_size(),
    prot=UC_PROT_READ,
    node=vf,
    offset=0
)

# Mount dynamic in-memory properties without writing to host disk
emu.vfs.mount_data(
    virt_path="/data/local.prop",
    data=b"ro.debuggable=0\nro.secure=1\n"
)
```

### 7. Memory Forensics (Hexdump & Telescope)

Inspect memory state and follow pointer chains (pwndbg / GEF style):

```python
from androidemu.utils.memory.helpers import hexdump, telescope

# Print formatted hex dump
print(hexdump(emu.mu, address=0x70000000, size=64))

# Dereference pointer chains on the stack
print(telescope(emu, address=emu.registers.v_sp, depth=6))
# 107ffe00: 4014b120 -> 40150240 (libnative.so: secret_key) -> "P@ssw0rd"
```

## ⚖️ Credits & Inspiration

AndroCorn is inspired by [ExAndroidNativeEmu](https://github.com/maiyao1988/ExAndroidNativeEmu) (by maiyao1988) and [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu) (by AeonLucid). Many thanks to their authors for the foundational work! ❤️