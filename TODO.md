1. Nested calls

2. execve -1 and -2 implementation
   In real Linux, if the path is not found, it returns -2 and doesn't kill current process.

3. Collect offsets to offset_cfg.py

4. Add regular expressions in const/devices.py

~~Refactor module names and paths~~

~~Improve find_symbol_globally in linker.~~

~~Move Linux errors to constants~~

~~Check more tests~~

~~Rename symbol hooks and fun hooks to stub_addr and hook_addr~~