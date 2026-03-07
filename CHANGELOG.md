# Changelog 2026.03.6

## Added
- ~~Support of nested calls: now you can call a native function from a hook function. Example:~~

```python
@native_method # Hook of malloc
def malloc(uc, size):
    # Some logging features here or additional operations
    # After all, you can call original method like this
    libc = emu.get_library("libc.so")
    ptr = emu.call_symbol(libc, 'malloc', size)
    if ptr == 0:
        raise MemoryError(f"Native malloc failed to allocate {size} bytes")
    return ptr
```

# Nested calls are temporarily disabled
###### idk how to realise it... i have bugs. help me

- Support of virtual time
- Support of multiple threads (futex full implementation)
- Support of some system libs high-level API
- New function `emu.call_function`
- New function `emu.get_library`
- New test file "test_urandom.py"
- Aliases: emu.get_pcb() `->` emu.pcb
- JNI Type Hints (not fully implemented yet)

## Updated
- Improved performance
- Improved VFS generator (50/50)
- Improved device configuration (not real good)
- Fixed file syscalls