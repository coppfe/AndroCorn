# Release v2.0.0 — Major Architecture & Runtime Overhaul (2026-09-18)

This is a **monumental milestone release** featuring a ground-up architectural redesign of the Execution Pipeline, Virtual File System, Memory Management, JNI Dispatcher, and Hooking Engine. Legacy subsystems, leaky abstractions, and god-object patterns have been eliminated in favor of a clean, deterministic, Linux-like hypervisor layer.

---

### 💥 Breaking Changes & Architectural Refactoring

* **Context-Driven Syscall Pipeline (`emu`-first)**:
  * Eradicated the raw `(mu, *args)` signature across the entire kernel subsystem. All interrupt and syscall callbacks now strictly accept `(emu: Emulator, *args)`.
  * Syscall handlers (`FileSystemIO`, `FileSystemManager`, `MemorySyscalls`, `SELinuxHandler`, `ARMSyscalls`, `SignalSyscalls`, `TimeSyscalls`) are now completely **stateless**. Removed redundant internal references (`self._mu`, `self._vfs`, `self._pcb`).
* **Calling Convention & Register Mapping Consolidation**:
  * Deleted `androidemu/native/helpers/args.py`. All calling convention logic (`read_args`, `write_args`, `read_syscall_args`, `set_return_val`) is now consolidated directly into `RegistersMapping`.
  * Dynamic virtual register access: Read via `regs.v_reg_x`, `regs.v_sp`, `regs.v_pc`, `regs.v_lr`, `regs.v_flags`, `regs.v_ret`. Write via property assignment (`regs.v_sp = new_sp`).
  * Fail-fast typing: Uninitialized `DynType` architecture defaults to `_current_arch = 0` to immediately prevent undefined bitwidth behaviors.
  * Corrected ARMv7 Thumb-mode detection and switching logic (`is_thumb()`, `set_thumb()`, `clear_thumb()`).
* **Memory Layout & True Heap Isolation**:
  * Separated emulator-internal allocations from the target process heap.
  * `0x60000000` (`EMU_HEAP_BASE`): Reserved exclusively for internal runtime data structures (DTV, TLS blocks, linker strings, arguments).
  * `0x70000000` (`BRK_BASE`): Strict 8MB deterministic Linux `[heap]` managed via `sys_brk`. Eliminates random allocations and matches `/proc/self/maps` bit-for-bit.
  * `0x80000000` (`MMAP_BASE`): Target memory area for dynamic anonymous mappings via `mmap` / `mmap2`.
* **Legacy VFS Purge**:
  * Completely removed `VirtualFile`, `VirtualFileTable`, and `vf_table` from `ProcessControlBlock`.
  * Removed legacy directories: `androidemu/objects/`, `androidemu/runtime/`, and `androidemu/kernel/backend/filesystem/helpers/`.
  * Virtual FD mapping now starts at standard POSIX ranges, dropping the `>= 1000` legacy restriction.
  * Renamed `config_path` to `environment` in `Emulator.__init__`.

---

### 🚀 New Features & Enhancements

#### 1. JNI Dynamic Arity Engine (`androidemu.java.jni`)
* **Auto-Arity Dispatcher (`__dyncall`)**:
  * Eradicated the hardcoded `(arg1, arg2, arg3, arg4)` limitation across all `Call<Type>Method` and `CallStatic<Type>Method` handlers.
  * Method signatures (`method.args_list`) are now dynamically inspected at invocation time. Arguments are read directly from CPU registers and the stack according to AAPCS/AAPCS64 conventions.
  * Cleaned up and restructured `JNIEnv` into clear, functional domains (Call Dispatcher, Object Lifecycle, Field Access, Strings/Arrays, Reflection, VM Control).

#### 2. Next-Gen Hooking Engine (`androidemu.native.hook`)
* **Modular `HookManager`**:
  * Unified public interface for all interception mechanisms via `emu.hook_manager`.
* **`InlineHook` Engine** (formerly `AddressHooker`):
  * Low-overhead function prologue/epilogue hooks with argument inspection, return value overriding, and execution replacement.
* **`MemoryWatchpoint` Engine**:
  * Granular memory read/write monitors with caller context inspection (`PC`, calling module, symbol name/offset). Designed specifically for reverse-engineering integrity checks, cryptographic key derivation, and unpackers.
* **`CrossModuleTracer`**:
  * High-performance execution tracer using `UC_HOOK_BLOCK`. Intercepts boundary transitions between user libraries and system libraries (`libc.so`) without instruction-level slowdown.

#### 3. Memory Forensics & Snapshot Engine (`androidemu.utils.memory`)
* **Zero-Copy Memory Snapshots (`create_snapshot` / `restore_snapshot`)**:
  * Instant state rollback for fuzzing and iterative function invocation. Captures CPU context, `brk` position, and writable (RW) memory pages without wasting cycles on immutable code segments.
* **Forensic Debugging Utilities**:
  * `hexdump(mu, addr, size)`: Formatted memory dumps with ASCII sidebars.
  * `telescope(emu, addr, depth)`: Multi-level pointer dereferencing engine (pwndbg/GEF style) with symbol and string auto-resolution.
  * `read_string_auto(mu, addr)`: Heuristic string decoder supporting UTF-8 and UTF-16LE auto-detection.
  * `find_bytes(mu, pattern, start, end)`: Chunked memory scanner for byte signatures.

#### 4. Extended Device Profiling System (`androidemu.data.models`)
* **Dataclass-Driven Hardware Models**:
  * Extensible, strictly typed models for `CPUInfo`, `GPUInfo`, `DisplayInfo`, `BatteryInfo`, `TelephonyInfo`, `BuildInfo`, and `SettingsSecure`.
* **Dynamic Environment Emulation**:
  * Integrated dynamic `am get-config` generator inside `cli/builtins.py` computed directly from `DisplayInfo` attributes.
  * Real-world telemetry resolution for `TelephonyManager` (`IMEI`, `IMSI`, network operator) and `Settings$Secure` (`android_id`, `GAID`).

#### 5. Unified Linux-like VFS Engine (`androidemu.kernel.fs`)
* **`VFSManager` Core**:
  * Object-oriented virtual node architecture (`HostFileNode`, `HostDirNode`, virtual nodes, character devices).
  * Built-in support for `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/binder`, `/dev/tty`, `/dev/ptmx`, `/dev/pts`.
  * Zero-deadlock in-memory `VirtualPipe` implementation.
  * SELinux extended attribute (`xattr`) labeling across virtual nodes.

#### 6. Next-Gen Device Profiling Engine (`androidemu.data`)
* **Dataclass-Driven Schemas**: Eradicated unstructured dictionaries in favor of strongly-typed models: `BuildInfo`, `CPUInfo`, `GPUInfo`, `DisplayInfo`, `BatteryInfo`, `TelephonyInfo`, `Net`, `Memory`, `Kernel`, and `SettingsSecure`.
* **Dynamic Environment Computation**:
  * Removed the hardcoded `"config"` string from configurations. The `am get-config` CLI response is now dynamically generated in real time from `DisplayInfo` (screen resolution, density, scaling factor, and locale).
  * Native telemetry for `TelephonyManager` (`IMEI`, `IMSI`, network operator name/codes) and `Settings.Secure` (`android_id`, Google Advertising ID `GAID`) is now fully configurable per profile.
* **Declarative Hardware Profiles**: Device profiles now accurately match real-world devices down to CPU architecture parts/revisions, OpenGL ES vendor/renderer strings, and battery/charge sensors.

---

### 🛠️ Bug Fixes & Stability Improvements

* **Thumb Mode Execution**: Fixed CPU CPSR flag evaluations preventing incorrect ARM/Thumb transitions during sub-task execution.
* **System Call Alignment & Corrections**:
  * Resolved double sign-extension bugs in `normalize_dirfd` across filesystem I/O operations.
  * Corrected time structure packing and timing parameter passing in `sys_clock_gettime` and `sys_gettimeofday`.
  * Hardened `sys_prctl` dispatching with modular option routing.
* **Memory Map Alignment**:
  * Fixed page boundary computations in `MemoryMap.map()` using proper `align_up` mechanics.
  * Optimized `/proc/self/maps` rendering with generation-based caching and binary search lookup (`bisect`).
* **Bionic Dynamic Linker**:
  * Fixed internal Nougat (API 25) `soinfo` list linking (`__dl__ZL6solist`).
  * Optimized symbol cache resolution to $O(1)$ first-definition lookup.