import logging
from typing import TYPE_CHECKING
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from ....const.flags import MAP_ANONYMOUS
from ....const.linux import EBADF
from ....data import layout as config
from ....types import ptr_t
from ....utils.memory import helpers

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

        mu = emu.mu
        ptr_sz = ptr_t.size

        off_r = remote_iov
        b = bytearray()
        for _ in range(riovcnt):
            rbase = helpers.read_ptr_sz(mu, off_r)
            iov_len = helpers.read_ptr_sz(mu, off_r + ptr_sz)
            b.extend(helpers.read_byte_array(mu, rbase, iov_len))
            off_r += 2 * ptr_sz

        off_l = local_iov
        has_read = 0
        total_len = len(b)
        for _ in range(liovcnt):
            lbase = helpers.read_ptr_sz(mu, off_l)
            liov_len = helpers.read_ptr_sz(mu, off_l + ptr_sz)

            chunk = b[has_read : has_read + liov_len]
            mu.mem_write(lbase, bytes(chunk))
            has_read += len(chunk)
            off_l += 2 * ptr_sz

            if has_read >= total_len:
                break

        return has_read

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