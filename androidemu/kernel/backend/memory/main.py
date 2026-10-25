import logging
from typing import TYPE_CHECKING

from ....const.flags import MAP_ANONYMOUS
from ....const.linux import EBADF
from ....data import layout as config
from ....types import ptr_t

if TYPE_CHECKING:
    from androidemu import Emulator

logger = logging.getLogger(__name__)


class MemorySyscalls:
    def __init__(self) -> None:
        self._brk_current: int = config.BRK_BASE

    def _handle_munmap(self, emu: 'Emulator', addr: int, len_in: int) -> int:
        return emu.memory.unmap(addr, len_in)

    def _handle_brk(self, emu: 'Emulator', brk_addr: int) -> int:
        heap_base = config.BRK_BASE
        heap_max = heap_base + config.BRK_SIZE

        if brk_addr == 0:
            return self._brk_current

        if brk_addr < heap_base or brk_addr > heap_max:
            return self._brk_current

        self._brk_current = brk_addr
        return self._brk_current

    def _handle_process_vm_readv(
        self, emu: 'Emulator', pid: int, local_iov: int, liovcnt: int, remote_iov: int, riovcnt: int, flag: int
    ) -> int:
        if pid != emu.pcb.pid:
            raise NotImplementedError("__process_vm_readv for other process is not supported")

        mem = emu.memory
        ptr_sz = ptr_t.size
        vec_sz = 2 * ptr_sz

        b = bytearray()
        off_r = remote_iov
        for _ in range(riovcnt):
            rbase = mem.read_ptr(off_r)
            iov_len = mem.read_ptr(off_r + ptr_sz)
            if iov_len > 0:
                b.extend(mem.read_bytes(rbase, iov_len))
            off_r += vec_sz

        total_len = len(b)
        if total_len == 0:
            return 0

        mv = memoryview(b)
        off_l = local_iov
        has_written = 0

        for _ in range(liovcnt):
            lbase = mem.read_ptr(off_l)
            liov_len = mem.read_ptr(off_l + ptr_sz)

            write_sz = min(liov_len, total_len - has_written)
            if write_sz > 0:
                mem.write_bytes(lbase, mv[has_written : has_written + write_sz])
                has_written += write_sz

            off_l += vec_sz

            if has_written >= total_len:
                break

        return has_written

    def _handle_mmap2(
        self, emu: 'Emulator', addr: int, length: int, prot: int, flags: int, fd: int, pgoffset: int
    ) -> int:
        if (flags & MAP_ANONYMOUS) or fd == 0xFFFFFFFF or fd == -1:
            res = emu.memory.map(addr, length, prot)
        else:
            handle = emu.vfs.get_handle(fd)
            if not handle:
                return -EBADF
            offset = pgoffset * 4096
            res = emu.memory.map(addr, length, prot, node=handle.node, offset=offset)

        logger.debug("mmap2 return %#08x", res)
        return res

    def _handle_mmap(
        self, emu: 'Emulator', addr: int, length: int, prot: int, flags: int, fd: int, offset: int
    ) -> int:
        if (flags & MAP_ANONYMOUS) or fd == 0xFFFFFFFF or fd == -1:
            res = emu.memory.map(addr, length, prot)
        else:
            handle = emu.vfs.get_handle(fd)
            if not handle:
                return -EBADF
            res = emu.memory.map(addr, length, prot, node=handle.node, offset=offset)

        logger.debug("mmap return %#016x", res)
        return res

    def _handle_madvise(self, emu: 'Emulator', start: int, len_in: int, behavior: int) -> int:
        return 0

    def _handle_mprotect(self, emu: 'Emulator', addr: int, len_in: int, prot: int) -> int:
        return emu.memory.protect(addr, len_in, prot)