from typing import TYPE_CHECKING

from ....const.linux import AT_FDCWD, EINVAL, EFAULT
from ....types import ptr_t
from ....utils.memory import helpers as memory_helpers

if TYPE_CHECKING:
    from androidemu import Emulator


class FileSystemIO:
    """
    Stateless VFS Input/Output syscalls.
    """

    def __init__(self) -> None:
        pass

    def _open(self, emu: 'Emulator', filename_ptr: int, flags: int, mode: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, filename_ptr) if filename_ptr else ""
        return emu.vfs.openat(AT_FDCWD, path, flags, mode)

    def _openat(self, emu: 'Emulator', dfd: int, filename_ptr: int, flags: int, mode: int) -> int:
        path = memory_helpers.read_utf8(emu.mu, filename_ptr) if filename_ptr else ""
        norm_dfd = memory_helpers.normalize_dirfd(dfd)
        return emu.vfs.openat(norm_dfd, path, flags, mode)

    def _close(self, emu: 'Emulator', fd: int) -> int:
        return emu.vfs.close(fd)

    def _read(self, emu: 'Emulator', fd: int, buf_addr: int, count: int) -> int:
        ret, data = emu.vfs.read(fd, count)
        if ret > 0:
            emu.mu.mem_write(buf_addr, data)
        return ret

    def _write(self, emu: 'Emulator', fd: int, buf_addr: int, count: int) -> int:
        data = emu.mu.mem_read(buf_addr, count)
        return emu.vfs.write(fd, data)

    def _writev(self, emu: 'Emulator', fd: int, vec: int, vlen: int) -> int:
        mu = emu.mu
        ptr_sz = ptr_t.size
        vec_sz = 2 * ptr_sz
        total_written = 0

        for i in range(vlen):
            addr = memory_helpers.read_ptr_sz(mu, vec + i * vec_sz)
            size = memory_helpers.read_ptr_sz(mu, vec + i * vec_sz + ptr_sz)
            chunk = mu.mem_read(addr, size)
            written = emu.vfs.write(fd, chunk)
            if written < 0:
                return written if total_written == 0 else total_written
            total_written += written

        return total_written

    def _lseek(self, emu: 'Emulator', fd: int, offset: int, whence: int) -> int:
        if ptr_t.size == 4 and (offset & 0x80000000):
            offset = offset - 0x100000000
        return emu.vfs.lseek(fd, offset, whence)

    def _llseek(self, emu: 'Emulator', fd: int, hi: int, lo: int, result_ptr: int, whence: int) -> int:
        offset = (hi << 32) | (lo & 0xFFFFFFFF)
        if offset & (1 << 63):
            offset -= (1 << 64)

        new_off = emu.vfs.lseek(fd, offset, whence)
        if new_off < 0:
            return -EINVAL

        try:
            emu.mu.mem_write(result_ptr, new_off.to_bytes(8, "little", signed=False))
            return 0
        except Exception:
            return -EFAULT

    def _ioctl(self, emu: 'Emulator', fd: int, cmd: int, arg1: int, arg2: int, arg3: int, arg4: int) -> int:
        return emu.vfs.ioctl(fd, cmd, arg1, emu.mu)

    def _poll(self, emu: 'Emulator', pollfd_ptr: int, nfds: int, timeout: int) -> int:
        mu = emu.mu
        ready = 0
        for i in range(nfds):
            ptr = pollfd_ptr + (i * 8)
            fd = int.from_bytes(mu.mem_read(ptr, 4), 'little')
            events = int.from_bytes(mu.mem_read(ptr + 4, 2), 'little')

            handle = emu.vfs.get_handle(fd)
            if not handle:
                mu.mem_write(ptr + 6, (0x0020).to_bytes(2, 'little'))  # POLLNVAL
                continue

            # POLLIN (0x1) | POLLOUT (0x4)
            revents = events & 0x0005
            mu.mem_write(ptr + 6, revents.to_bytes(2, 'little'))
            if revents:
                ready += 1

        return ready

    def _ppoll(self, emu: 'Emulator', pollfd_ptr: int, nfds: int, timeout_ts_ptr: int, sigmask_ptr: int) -> int:
        return self._poll(emu, pollfd_ptr, nfds, 0)