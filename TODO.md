1. execve -1 and -2 implementation
   In real Linux, if the path is not found, it returns -2 and doesn't kill current process.

2. Collect offsets to offset_cfg.py

3. More flexability in VFS and Kernel: SELinux, ContentGenerator, Device File Properties.

4. Make Correct File Stats

5. Type syscall functions by own `types`

6. Make it faster as possible.

7. Remove fcntl module!!! Not working on Windows and not working with Virtual Files.

~~ Types in syscalls, correct int transformation from native. ~~

~~Nested calls~~

~~Refactor module names and paths~~

~~Improve find_symbol_globally in linker.~~

~~Move Linux errors to constants~~

~~Rename symbol hooks and fun hooks to stub_addr and hook_addr~~