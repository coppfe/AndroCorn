# Custom VFS Devices

Custom virtual character/block devices can be added to the filesystem by subclassing `VfsNode` and registering the node into `emu.vfs`.

---

## Device Implementation Matrix

| Method | Parameters | Description |
| :--- | :--- | :--- |
| `__init__` | `name`, `mode`, `uid`, `gid`, `dev`, `rdev` | Sets file type, access permissions (`0o020666` for character devices), and device IDs (`rdev`). |
| `check_permission` | `ctx`, `flags` | Validates read/write access. Return `0` for success or Linux error code (e.g., `-EACCES`). |
| `read` | `offset`, `count` | Handles incoming `sys_read` operations. Returns `bytes`. |
| `write` | `offset`, `data` | Handles incoming `sys_write` operations. Returns processed byte count. |
| `ioctl` | `cmd`, `arg`, `mu` | Handles device control operations. Returns `0` on success or `-ENOTTY` for unsupported commands. |

---

## Example: Registering a Character Device

```python
from androidemu import Emulator
from androidemu.kernel.fs.node import VfsNode
from androidemu.const.linux import ENOTTY

class CryptoHardwareDevice(VfsNode):
    def __init__(self):
        super().__init__(
            name="/dev/crypto_hw",
            mode=0o020666,          # S_IFCHR | 0666
            uid=0,
            gid=0,
            dev=0x0005,             # devtmpfs
            rdev=(10 << 8) | 100    # Major: 10 (misc), Minor: 100
        )
        self.setxattr("security.selinux", b"u:object_r:crypto_device:s0\x00")
        self._buffer = bytearray()

    def check_permission(self, ctx, flags: int) -> int:
        return 0

    def write(self, offset: int, data: bytes) -> int:
        self._buffer.extend(data)
        return len(data)

    def read(self, offset: int, count: int) -> bytes:
        chunk = bytes(self._buffer[:count])
        del self._buffer[:count]
        return chunk

    def ioctl(self, cmd: int, arg: int, mu) -> int:
        if cmd == 0xC0044301:
            mu.mem_write(arg, (0x1337).to_bytes(4, "little"))
            return 0
        return -ENOTTY

# Mount device into the Virtual File System
emu = Emulator(init_sys_libs=False)
emu.vfs.mount("/dev/crypto_hw", CryptoHardwareDevice())