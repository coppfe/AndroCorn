import logging
import os
import platform
import select


from ......utils.generators.vfs_content import ContentGenerator
from ......objects.virtual_file import VirtualFile
from ......const.linux import *

from unicorn import Uc
from unicorn.arm_const import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ......emulator import Emulator
    from ......pcb import Pcb
    from .fs_helpers import FSHelpers

class FSIOHelpers:
    def __init__(self, emulator: 'Emulator', content_generator: 'ContentGenerator', fs_helper: 'FSHelpers'):
        self.__emu: 'Emulator' = emulator
        self.__pcb: 'Pcb' = emulator.pcb

        self.__generator: 'ContentGenerator' = content_generator
        self.__fs_helpers: 'FSHelpers' = fs_helper

        self.g_isWin: bool = platform.system() == "Windows"

    def _do_poll(self, mu, pollfd_ptr, nfds, timeout):
        VIRT_READY = 0x0005 # POLLIN | POLLOUT
        virtual_ready_count = 0
        poll_list = []
        p = select.poll() if hasattr(select, "poll") else None
        
        for i in range(nfds):
            ptr = pollfd_ptr + (i * 8)
            guest_fd = int.from_bytes(mu.mem_read(ptr, 4), 'little')
            events = int.from_bytes(mu.mem_read(ptr + 4, 2), 'little')

            vf = self.__pcb.virtual_files.get_fd_detail(guest_fd)
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
        file_path = self.__fs_helpers._translate_path(filename)
        if os.path.isdir(file_path):
            logging.warning("Failed to open file '%s'! It's a directory", filename)
            # WARNING! If you in this branch -> your lib maybe work not correct or it's env check!
            # If you here because of test_native, it's ok (not actually), bcs vfs util named as gen_map
            # Does not return correct address and path of app_process. I don't know why.
            return -EISDIR
        
        is_virtual = self.__generator.is_virtual(filename)
        return VirtualFile.open(self.__emu, filename, file_path, flags, is_virtual)
    
    def _close_file(self, mu, fd):
        vfs = self.__pcb.virtual_files
        
        if vfs.has_fd(fd):
            vfs.remove_fd(fd)
            
            if hasattr(self, '__fs_helpers'):
                self.__fs_helpers._del_fd_link(fd)
                
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