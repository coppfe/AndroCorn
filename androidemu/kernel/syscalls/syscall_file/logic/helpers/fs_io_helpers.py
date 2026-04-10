import logging
import os
import platform
import select


from ......utils import misc_utils
from ......utils.generators.vfs_content import ContentGenerator

from unicorn import Uc
from unicorn.arm_const import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ......emulator import Emulator
    from .....pcb import Pcb
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
            fd = int.from_bytes(mu.mem_read(ptr, 4), 'little')
            events = int.from_bytes(mu.mem_read(ptr + 4, 2), 'little')

            is_virt = self.__pcb.virtual_files.get_fd_detail(fd).is_virtual
            info = {"fd": fd, "events": events, "ptr": ptr, "is_virt": is_virt, "revents": 0}
            
            if is_virt:
                res = events & VIRT_READY
                if res:
                    info["revents"] = res
                    virtual_ready_count += 1
            elif p:
                try: p.register(fd, events)
                except OSError: info["revents"] = 0x0008 # POLLERR
            poll_list.append(info)

        actual_timeout = 0 if virtual_ready_count > 0 else timeout
        if p and any(not x["is_virt"] for x in poll_list):
            os_results = {fd: rev for fd, rev in p.poll(actual_timeout)}
            for info in poll_list:
                if not info["is_virt"] and info["fd"] in os_results:
                    info["revents"] = os_results[info["fd"]]

        for info in poll_list:
            mu.mem_write(info["ptr"] + 6, int(info["revents"]).to_bytes(2, 'little'))

        return virtual_ready_count + sum(1 for x in poll_list if not x["is_virt"] and x["revents"] > 0)
    
    def _open_file(self, mu, filename, flags):
        file_path = self.__fs_helpers._translate_path(filename)
        is_virtual, path_info = self.__generator.prepare_path(filename, file_path, ignore_handler=True) # we don't need generate content.
        if is_virtual:
            return self.__pcb.virtual_files.add_virtual_fd(filename, path_info)

        original_flags = flags
        
        access_mode = original_flags & 3
        if access_mode == 0:   # O_RDONLY
            real_flags = os.O_RDONLY
        elif access_mode == 1: # O_WRONLY
            real_flags = os.O_WRONLY
        elif access_mode == 2: # O_RDWR
            real_flags = os.O_RDWR
        else:
            real_flags = os.O_RDONLY # Дефолт

        if (original_flags & 0o100):      # O_CREAT
            real_flags |= os.O_CREAT
        if (original_flags & 0o2000):     # O_APPEND
            real_flags |= os.O_APPEND
        if (original_flags & 0o40000):    # O_DIRECTORY
            real_flags |= getattr(os, 'O_DIRECTORY', 0)
        if (original_flags & 0o10000000): # O_PATH
            real_flags |= getattr(os, 'O_PATH', 0)

        try:

            fd = misc_utils.my_open(file_path, real_flags)

        except PermissionError:
            if os.path.isdir(file_path):
                return -21  # EISDIR
            
            return -13      # EACCES
        
        except FileNotFoundError:
            return -2       # ENOENT
        
        self.__pcb.virtual_files.add_fd(filename, file_path, fd)
        logging.info("open [%s][0x%x] return fd %d" % (file_path, flags, fd))
        self.__create_fd_link(fd, file_path)
        return fd
        
    def _close_file(self, mu, fd):
        vf = self.__pcb.virtual_files.get_fd_detail(fd)
        try:

            if (self.__pcb.virtual_files.has_fd(fd)):
                file = self.__pcb.virtual_files.get_fd_detail(fd)
                if not file.is_virtual: os.close(fd)
                self.__pcb.virtual_files.remove_fd(fd)
                self.__fs_helpers._del_fd_link(fd)
            else:

                # Previously closed items will return 0, consistent with Android system behavior.
                logging.warning("fd 0x%08X not in fds maybe has closed. Return 0"%fd)
                return 0
            
        except OSError as e:
            logging.warning("fd %d close error."%fd)
            return -1
        
        return 0
    
    def __create_fd_link(self, fd, target):
        if (self.g_isWin):
            # TODO?
            return

        if (fd >= 0):
            pid = self.__pcb.pid
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self.__fs_helpers._translate_path(fdbase)
            if (not os.path.exists(fdbase)):
                os.makedirs(fdbase)

            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)

            full_target = os.path.abspath(target)
            os.symlink(full_target, p, False)

    def _del_fd_link(self, fd):
        if (self.g_isWin):
            # TODO?
            return 

        if (fd >= 0):
            pid = self.__pcb.pid
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self.__fs_helpers._translate_path(fdbase)
            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)