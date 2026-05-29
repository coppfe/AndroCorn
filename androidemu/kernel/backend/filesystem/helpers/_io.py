import logging
import os
import select

from .....objects.virtual_file import VirtualFile
from .....const.linux import *
from .....const.flags import VIRT_READY

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ....dev.content import ContentGenerator
    from .....core.process.pcb import ProcessControlBlock
    from .utils import FileSystemUtils

class FileSystemIOUtils:
    def __init__(self, pcb: 'ProcessControlBlock', content_generator: 'ContentGenerator', fs_helper: 'FileSystemUtils'):
        self._pcb: 'ProcessControlBlock' = pcb

        self._generator: 'ContentGenerator' = content_generator
        self._fs_helpers: 'FileSystemUtils' = fs_helper

    def _do_poll(self, mu, pollfd_ptr, nfds, timeout):
        virtual_ready_count = 0
        poll_list = []
        p = select.poll() if hasattr(select, "poll") else None
        
        for i in range(nfds):
            ptr = pollfd_ptr + (i * 8)
            guest_fd = int.from_bytes(mu.mem_read(ptr, 4), 'little')
            events = int.from_bytes(mu.mem_read(ptr + 4, 2), 'little')

            vf = self._pcb.virtual_files.get_fd_detail(guest_fd)
            if not vf:
                mu.mem_write(ptr + 6, (0x0020).to_bytes(2, 'little'))
                continue

            info = {"guest_fd": guest_fd, "vf": vf, "ptr": ptr, "revents": 0}
            
            if vf.is_virtual:
                res = events & VIRT_READY
                if res:
                    info["revents"] = res
                    virtual_ready_count += 1
            elif p:
                try:
                    p.register(vf.descriptor, events)
                except OSError:
                    info["revents"] = 0x0008 # POLLERR
            
            poll_list.append(info)

        actual_timeout = 0 if virtual_ready_count > 0 else timeout
        
        if p and any(not x["vf"].is_virtual for x in poll_list):
            os_results = {fd: rev for fd, rev in p.poll(actual_timeout)}
            for info in poll_list:
                if not info["vf"].is_virtual:
                    host_fd = info["vf"].descriptor
                    if host_fd in os_results:
                        info["revents"] = os_results[host_fd]

        for info in poll_list:
            mu.mem_write(info["ptr"] + 6, int(info["revents"]).to_bytes(2, 'little'))

        return virtual_ready_count + sum(1 for x in poll_list if not x["vf"].is_virtual and x["revents"] > 0)
    
    def _open_file(self, mu, filename, flags):
        if filename == '':
            logging.warning("Failed to open file! Path is None")
            return -ENOENT
        
        file_path = self._fs_helpers._translate_path(filename)
        
        if os.path.isdir(file_path):
            logging.warning("Failed to open file '%s'! It's a directory", filename)
            return -EISDIR
            
        is_virtual = self._generator.is_virtual(filename)
        try: r =  VirtualFile.open(self._pcb, filename, file_path, flags, is_virtual)
        except Exception as e:
            logging.warning("Failed to open file %s! %s", filename, e)
            return -ENOENT
        return r
    
    def _close_file(self, mu, fd):
        vfs = self._pcb.virtual_files
        
        if vfs.has_fd(fd):
            vfs.remove_fd(fd)
            
            self._fs_helpers._del_fd_link(fd)
                
            return 0
        else:
            logging.warning("fd 0x%08X not in fds, maybe already closed.", fd)
            return 0
    
    def __create_fd_link(self, guest_fd, target):
        return 0
        
        # if not os.path.exists(fdbase):
        #     os.makedirs(fdbase, exist_ok=True)

        # link_path = os.path.join(fdbase, str(guest_fd))
        # if os.path.exists(link_path):
        #     os.remove(link_path)

        # try:
        #     full_target = os.path.abspath(target)
        #     os.symlink(full_target, link_path)
        # except OSError:
        #     pass

    def _del_fd_link(self, fd):
        return 0