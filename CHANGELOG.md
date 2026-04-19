# Changelog 2026.04.19

## Added:
* New lib: `cpp_demangle`
* New file: `registers.py`
* New file: `offsets/arm64.py` and `offsets/arm32.py`
* New file: `execve.py`
* New file: `test_perror.py`
* Moved `vdstat.py` to `androidemu/objects`
* New `load_library` option: `demangle`: `bool`
* New `ptrace` code: Yama
* Syscall implementation of `fork` and `execve`
* Windows backward compatibility fixed (and linux probably too)
* Fixed classes slots: removed duplications
- New `Emulator` methods:
  * `sys_reg_write`
  * `sys_reg_read`
- New `VirtualFile` methods:
  * `close`
  * `read`
  * `write`
  * `seek`
  * `get_size`
* Docs-Strings in `Emulator`
* File Descriptors isolation
* Copy-On-Write system (primitive)
* New util: `BionicTLSUtils`
* New config field: `device.config` for adbd config
* Other things that I can't remember

## Fixed:
* TLS Slots & Offsets

## Removed:
* Magic create of class `Android LogCat Parser` for writev methods.
* pthread_internal fields in `BionicTLS` (libc filled itself after initialization)
* Deleted Release (project in beta testing)

# Comment:
In this change emulator now support system registers that's not provided in Unicorn! Check them:
`utils/cpu.py`
`constants/registers.py`

# Now address 0x1000 is reserved for emulator!!!

Emulator is getting too smart and later i think it will be eat more RAM
So now i think about some optimizations.
If someone in this world is interested in help, HEEEELP MEEEE!!!