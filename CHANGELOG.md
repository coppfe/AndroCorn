# Changelog 2026.05.29

## Changed:

* Full Reworked environment of project
* `netive_method` now return the `Emulator` object as first arg
* Add Nested Calls!!!
* Add correct support for dlopen!!!
* Add `define` decorator for auto-transform args
* Add custom `C-like types`
* Add `GlobalContextMachine` class for better syscall emulation later. Access to context -> `Emulator.ctx`
* Add `arguments` dir as try to remove `Emulator` from god-object position
* Add implement of `_gen_maps` for proc/self/maps
* Add suspend task support in `Scheduler`
* Add correct work for next syscall types: `signals`
* Reworked file stats

## Removed:
* `Emulator.ptr_size` -> Now use `ptr_t.size` from `types.alias`
* `Pcb` now named as `ProcessControlBlock`
* `ProcessControlBlock` now have only virtual file table. Info about process moved to `Emulator.ctx`. More about structs in phantom classes: `data/states`
