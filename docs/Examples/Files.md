## Example of working with Virtual File System in RunTime

```python
from androidemu.emulator import Emulator
from androidemu.const import emu_const

emulator = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32)
libcm = emulator.get_library("libc.so")

# just get full code from tests/test_urandom
emu = emulator
libcm = emu.get_library("libc.so")

path_ptr = emu.call_symbol(libcm, 'malloc', 64)
emu.mu.mem_write(path_ptr, b"/dev/urandom\0")

# open("/dev/urandom", O_RDONLY=0)
fd = emu.call_symbol(libcm, 'open', path_ptr, 0)
print(f"    Virtual FD: {fd}")

vf = emulator.pcb.virtual_files.get_fd_detail(fd)

print(f"Info about vf: {vf.__dict__}")

vf.write(b"Hello world\n\x00")
vf.seek(0, 0)

read_size = 11
read_buf = emu.call_symbol(libcm, 'malloc', read_size)
res = emu.call_symbol(libcm, 'read', fd, read_buf, read_size)

data = emu.mu.mem_read(read_buf, read_size)
print(f"    Read result: {res} bytes, data: {data}")
```

Same with read, open and other