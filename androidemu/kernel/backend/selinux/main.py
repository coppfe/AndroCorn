from typing import TYPE_CHECKING
from ....const.linux import AT_FDCWD, ENOENT, ENODATA, ERANGE, EBADF
from ....utils.memory import helpers

if TYPE_CHECKING:
    from unicorn import Uc

    from androidemu import Emulator
    from ...fs.node import VfsNode


class SELinuxHandler:
    def __init__(self):
        pass
    
    def _getxattr_common(self, mu: 'Uc', node: 'VfsNode', name_ptr: int, value_ptr: int, size: int) -> int:
        if not node:
            return -ENOENT

        attr_name = helpers.read_utf8(mu, name_ptr)
        val = node.getxattr(attr_name)
        if val is None:
            return -ENODATA

        val_len = len(val)
        if size == 0:
            return val_len

        if size < val_len:
            return -ERANGE

        mu.mem_write(value_ptr, val)
        return val_len

    def _getxattr(self, emu: 'Emulator', path_ptr: int, name_ptr: int, value_ptr: int, size: int) -> int:
        mu = emu.mu
        
        path = helpers.read_utf8(mu, path_ptr) if path_ptr else ""
        
        node = emu.vfs.resolve_node(AT_FDCWD, path, follow_symlinks=True)
        return self._getxattr_common(mu, node, name_ptr, value_ptr, size)

    def _lgetxattr(self, emu: 'Emulator', path_ptr: int, name_ptr: int, value_ptr: int, size: int) -> int:
        mu = emu.mu

        path = helpers.read_utf8(mu, path_ptr) if path_ptr else ""
        node = emu.vfs.resolve_node(AT_FDCWD, path, follow_symlinks=False)
        return self._getxattr_common(mu, node, name_ptr, value_ptr, size)

    def _fgetxattr(self, emu: 'Emulator', fd: int, name_ptr: int, value_ptr: int, size: int) -> int:
        mu = emu.mu
        
        handle = emu.vfs.get_handle(fd)
        if not handle:
            return -EBADF
        return self._getxattr_common(mu, handle.node, name_ptr, value_ptr, size)