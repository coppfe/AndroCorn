# Example of working with Virtual File System

## Native

```python
from androidemu import Emulator
from androidemu.const import emu_const
from androidemu.utils.memory import helpers

emu = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32)
libcm = emu.get_library("libc.so")

path_ptr = emu.call_symbol(libcm, 'malloc', 64)
helpers.write_utf8(emu.mu, path_ptr, "/dev/urandom")

# open("/dev/urandom", O_RDONLY = 0)
fd = emu.call_symbol(libcm, 'open', path_ptr, 0)
print(f"[+] Native open() returned Virtual FD: {fd}")

handle = emu.vfs.get_handle(fd)
print(f"[+] VFS Handle: Node={handle.node.name}, Offset={handle.offset}, Flags=0x{handle.flags:X}")

read_size = 16
read_buf = emu.call_symbol(libcm, 'malloc', read_size)
bytes_read = emu.call_symbol(libcm, 'read', fd, read_buf, read_size)

random_data = emu.mu.mem_read(read_buf, bytes_read)
print(f"[+] Native read() result: {bytes_read} bytes -> {random_data.hex()}")

emu.call_symbol(libcm, 'close', fd)
emu.call_symbol(libcm, 'free', path_ptr)
emu.call_symbol(libcm, 'free', read_buf)

# [+] Native open() returned Virtual FD: 102
# [+] VFS Handle: Node=/dev/urandom, Offset=0, Flags=0x20000
# [+] Native read() result: 16 bytes -> 2508de66410cfb0fd281a75d2f584300
```

## API
```python
from androidemu import Emulator
from androidemu.const import emu_const

emu = Emulator(vfs_root="vfs", arch=emu_const.ARCH_ARM32)

fd = emu.vfs.openat(dirfd=-100, path="/dev/urandom", flags=0, mode=0)

status, data = emu.vfs.read(fd, count=16)
print(f"[+] VFS Read: {len(data)} bytes -> {data.hex()}")

# whence: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END
new_offset = emu.vfs.lseek(fd, offset=0, whence=0)

emu.vfs.close(fd)
```

## File Mounting
```python
...

# Mount file to memory
vf = emulator.vfs.mount_file(
    "/data/app/io.github.vvb2060.mahoshojo/base.apk", 
    "vfs/data/app/io.github.vvb2060.mahoshojo/base.apk", 
    uid=1000
)

apk_size = vf.get_size()
emulator.memory.map( # Map it for /proc/self/maps
    0,
    size=apk_size,
    prot=UC_PROT_READ,
    node=vf,
    offset=0
)
```

## Data Mounting

```python
# mount_data(virt_path, data, mode=0o100644, uid=0, gid=0)
config_bytes = b"ro.build.version.sdk=25\nro.debuggable=0\n"
node = emu.vfs.mount_data(
    virt_path="/data/local.prop",
    data=config_bytes,
    mode=0o100644,
    uid=10001,
    gid=10001
)
```