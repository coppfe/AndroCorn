1. execve -1 and -2 implementation
   In real Linux, if the path is not found, it returns -2 and doesn't kill current process. Maybe

2. Collect offsets to offset_cfg.py

3. Type syscall functions by own `types`

4. Implement Android 8+ Property Dir Support.

~~More flexability in VFS and Kernel: SELinux, ContentGenerator, Device File Properties.~~

~~Make Correct File Stats~~

~~Remove fcntl module!!! Not working on Windows and not working with Virtual Files.~~

~~Types in syscalls, correct int transformation from native.~~

~~Nested calls~~

~~Refactor module names and paths~~

~~Improve find_symbol_globally in linker.~~

~~Move Linux errors to constants~~

~~Rename symbol hooks and fun hooks to stub_addr and hook_addr~~