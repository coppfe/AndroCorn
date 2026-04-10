# Changelog 2026.04.10

## Added
- New utils:
    - `parsers/android/logcat.py`
- New constant files:
    - `kernel/flags.py`
- New tool:
    - `gen_jni_env_map.py`
- New test:
    - `test_native.py` (armv7a, libcms.so)

## Updates
- Updated package struct: Now syscalls are grouped by category.
- Updated PCB: New field: `virtual_files` Full implement work with virtual file system.
- Updated JNI Env: Now args parsing in file `helpers/jni_native.py`. Optimized and fixed some bugs.
- Updated config: Now configs are more flexable.
- Updated `Hooker`: replaced `uc.mem_read` to `self._addr_to_hook[address & ~1]` for faster lookup handlers.
- Updated `init_fun_hooks`: Now you can hook function by name, or by raw address.
- Removed f-strings
- Optimizied `native_method` decorator
- Fully implement of ContentGenerator (VFS Content Generator)

# Fixed
- Temporary removed nested call `malloc` and `free` from `highlevel/libc.py`

# Removed
- keystone_in dir 
    ###### actually, it's on my pc, but in the project it's never used for something.