# AndroCorn Documentation

**AndroCorn** is an advanced, kernel-free user-space emulation framework for Android native ARM/ARM64 libraries built on top of the Unicorn Engine.

It provides a fully simulated Android OS user-space environment, allowing you to load and execute heavily obfuscated `.so` files, anti-tamper protectors, and cryptors seamlessly on Windows, macOS, and Linux.

---

## Key Highlights of Version 2.0

* **Zero God-Objects**: Modular, context-driven design where interrupts and syscalls operate on pure stateless abstractions.
* **Deterministic Memory Mapping**: Strict segmentation between emulator-internal storage (`0x60...`), process `[heap]` (`0x70...`), dynamic `mmap` (`0x80...`), and the stack (`0x10...`).
* **POSIX VFS with In-Memory IPC**: Full object-oriented filesystem node architecture with support for character devices (`/dev/null`, `/dev/urandom`, `/dev/binder`, `/dev/ptmx`), dynamic procfs (`/proc/self/maps`), and non-blocking `VirtualPipe`.
* **Auto-Arity JNI Dispatcher**: Dynamic argument extraction supporting methods with arbitrary parameter counts without hardcoded limits.
* **Modern Hooking & Forensics**: Integrated `InlineHook`, caller-context `MemoryWatchpoint`, and block-level `CrossModuleTracer`.
* **State Rollback**: Instant zero-copy memory snapshots for fuzzing and repetitive native function evaluation.

---

## Module Index

::: androidemu.core.emulator.Emulator
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.core.registers.RegistersMapping
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.kernel.fs.manager.VFSManager
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.native.hook.manager.HookManager
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.internal.linker.AndroidLinker
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.utils.memory.map.MemoryMap
    options:
      filters: ["!^_"]
      show_root_heading: true