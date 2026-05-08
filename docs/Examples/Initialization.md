## Quick Usage Example:

Just run this script in any file after installing AndroCorn!

```python
from androidemu.emulator import Emulator
from androidemu.const import emu_const

# Initialize AndroCorn
emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32) # Or ARCH_ARM64
libcm = emulator.get_library("libc.so")

fmt_str = b"Hello from AndroCorn! If you can see this message -> everything was inited correctly\n\x00"
fmt_ptr = emulator.call_symbol(libcm, "malloc", len(fmt_str))
emulator.mu.mem_write(fmt_ptr, fmt_str)

emulator.call_symbol(libcm, "printf", fmt_ptr)
emulator.call_symbol(libcm, "free", fmt_ptr)
```