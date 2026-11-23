## [Unreleased] - 2026-11-23

### 🤝 Contributors & Acknowledgements
Special thanks to the contributors who helped make this release possible:
- Huge thanks to [@UserN0tAdmin](https://github.com/UserN0tAdmin) for contributing the new JNI methods, comprehensive test suite, and the floating-point argument passing implementation!

### ⚠️ Breaking Changes
- **core/registers**: Complete overhaul of CPU register mapping and access semantics (`androidemu/core/registers.py`). Added native support for SIMD/FP vector registers (`Q0-Q7`, `D0-D7`). Completely redesigned register read/write subsystems for higher performance and safety.
- **core/memory**: Replaced direct Unicorn memory operations across the entire kernel backend with `MemoryMap` abstractions (covers `sysproc`, `filesystem`, `selinux`, and `memory`).
- **java/jni**: Massive JNI subsystem refactoring:
  - Extracted dispatch and invocation logic into dedicated `invoker.py`.
  - Added native signature parsing (`signature.py`) and explicit Java exception propagation.
  - Rewrote argument passing and floating-point calling convention handling.
- **internal/linker**: Decomposed monolithic `linker.py` into a modular package architecture (`androidemu/internal/linker/`): `elfmap`, `factory`, `libres`, `runtime`, and `soinfo`.

---

### 🚀 Features

#### Android Runtime & Java Layer
- **Classes & Framework Stubs**:
  - Added Android OS services and IPC primitives: `Binder`, `Parcel`, `ServiceManager`.
  - Added crypto/security stubs: `X509Certificate`, `Key`, and certificate chain handling.
  - Added core system classes: `LocationManager`, `Settings.Secure`, `Build`, `InputStream`, `File`, and `Objects`.
  - Implemented missing package manager methods (`PackageManager`).
- **Field & Class Definition**:
  - Implemented dynamic field inheritance and fixed MRO/Python inheritance edge-cases.
  - Added support for lambda resolvers in field descriptors with direct emulator context binding.

#### Native & Linker
- **Bionic / Linker**:
  - Added system 64-bit dynamic linker binary (`vfs/system/bin/linker64`).
  - Improved TLS initialization, DTV builder, and Bionic module descriptors.
  - Implemented basic native function calling convention protocols in `androidemu/native/helpers/method.py`.

#### Kernel Backend & Syscalls
- **Syscalls**:
  - Implemented `pread64` syscall handler for both ARM32 and ARM64 architectures.
  - Added support for new `prctl` control options.
- **Filesystem & SElinux**:
  - Added `/proc/self` directory node support for SELinux process context lookup.

---

### 🛠️ Improvements & Optimizations
- **Hooking & Tooling**: Pruned unused hook engines and utility proxies from `HookManager`; advanced instrumentation utilities migrated into `androcorn_native_tools`.
- **Boot Chain**: Streamlined and cleaned up emulator lifecycle initialization in `Emulator`.
- **Memory & Structs**: Optimized memory map utilities, struct serialization (`struct_writer.py`), and TLS helper layouts.
- **CPU Utils**: Removed redundant dictionary allocations for custom registers in favor of tuple constants.

---

### 🐛 Bug Fixes
- **sysproc**: Fixed NULL-pointer dereference vulnerability in `futex` when handling invalid `uaddr`.
- **vfs**: Fixed mount point path resolution in filesystem manager.
- **cpu/scheduler**: Fixed target address and register corruption issues during function invocations.
- **native/dl**: Corrected symbol lookup resolution in `libdl_sym.py`.
- **tests**: Fixed harness breaking changes and aligned test suite with new JNI/FP argument readers.