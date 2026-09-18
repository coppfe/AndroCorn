from androidemu.core.emulator import Emulator
from androidemu.const.emu_const import ARCH_ARM32
from androidemu.const.linux import AT_FDCWD, O_RDONLY

emulator = Emulator(
    vfs_root="vfs",
    arch=ARCH_ARM32,
    init_sys_libs=False
)

pid = emulator.pcb.pid
print("=" * 70)
print(f"[+] PID: {pid}")

target = emulator.vfs.readlink(AT_FDCWD, "/proc/self")
print(f"[+] Symlink /proc/self -> pointers at: '{target}'")

fd = emulator.vfs.openat(AT_FDCWD, "/proc/self", O_RDONLY, 0)
print(f"[+] Dir /proc/self listed (FD: {fd})")

handle = emulator.vfs.get_handle(fd)
entries = handle.node.getdents()

print("\n[+] Listing /proc/self/ (getdents):")
for name, d_type, ino in entries:
    type_name = "DIR" if d_type == 4 else ("SYMLINK" if d_type == 10 else "FILE")
    print(f"    /{name:<15} [{type_name:<7}] (inode: {ino})")

emulator.vfs.close(fd)

print("\n" + "=" * 70)
print("[+] Dump /proc/self/mountinfo:")
print("-" * 70)

fd_mount = emulator.vfs.openat(AT_FDCWD, "/proc/self/mountinfo", O_RDONLY, 0)
_, content = emulator.vfs.read(fd_mount, 8192)
print(content.decode("utf-8"))
emulator.vfs.close(fd_mount)

print("=" * 70)
print("[+] First lines from /proc/self/status:")
print("-" * 70)

fd_status = emulator.vfs.openat(AT_FDCWD, "/proc/self/status", O_RDONLY, 0)
_, status_data = emulator.vfs.read(fd_status, 512)
print("\n".join(status_data.decode("utf-8").strip().splitlines()[:6]))
emulator.vfs.close(fd_status)