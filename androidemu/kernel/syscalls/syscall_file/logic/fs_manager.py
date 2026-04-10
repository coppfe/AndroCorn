import logging
import os
import platform
import struct
import random

from .....utils.memory import memory_helpers
from .....utils.generators.vfs_content import ContentGenerator

from .helpers.structs.vdstat import VirtualDeviceStat
from .....utils.files import file_helpers

from .....const.linux import *
from .....const.metatags import *
from .....const import emu_const
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .....emulator import Emulator
    from ....pcb import Pcb
    from .helpers.fs_helpers import FSHelpers

if platform.system() == "Linux":
    import fcntl

class VirtualFileSystemCalls:

    def __init__(self, emulator: 'Emulator', content_generator: 'ContentGenerator', fs_helper: 'FSHelpers'):
        self.__emu: 'Emulator' = emulator
        self.__pcb: 'Pcb' = self.__emu.pcb

        self.__generator = content_generator
        self.__fs_helpers = fs_helper

        # self.__tid = self.__emu.scheduler.get_current_tid()
        
        self.g_isWin = platform.system() == "Windows"

    @PROXY
    def _stat64(self, mu, filename_ptr, buf_ptr): # # VFS manager
        return self.__fs_helpers._internal_path_stat_handler(mu, memory_helpers.read_utf8(mu, filename_ptr), buf_ptr, True)

    @PROXY
    def _lstat64(self, mu, filename_ptr, buf_ptr): # # VFS manager
        return self.__fs_helpers._internal_path_stat_handler(mu, memory_helpers.read_utf8(mu, filename_ptr), buf_ptr, False)

    @PROXY
    def _fcntl(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        if (self.g_isWin):
            return 0
        r = fcntl.fcntl(fd, cmd, arg1)
        return r

    @PROXY
    def _fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        path = self.__fs_helpers._dirfd_2_path(dirfd, memory_helpers.read_utf8(mu, pathname_ptr))
        if path is None: return -1
        follow = not (flags & 0x100) # AT_SYMLINK_NOFOLLOW

        return self.__fs_helpers._internal_path_stat_handler(mu, path, buf, follow)
    
    def _unlink(self, mu, path_ptr):
        path = memory_helpers.read_utf8(mu, path_ptr)
        logging.debug("unlink call path [%s]"%path)
        return 0

    def _fstat64(self, mu, fd, stat_ptr): # # VFS manager
        vf = self.__pcb.virtual_files.get_fd_detail(fd)
        if vf.is_virtual:
            dev_name = vf.name
            vstat = VirtualDeviceStat(fd, dev_name, self.__emu.time_manager)
            uid = self.__fs_helpers._get_config_uid(dev_name)

            if self.__emu.arch == emu_const.ARCH_ARM32:
                file_helpers.stat_to_memory2(mu, stat_ptr, vstat, uid, vstat.st_mode, self.__emu.config)
            else:
                file_helpers.stat_to_memory64(mu, stat_ptr, vstat, uid, vstat.st_mode, self.__emu.config)
            return 0

        detail = self.__pcb.virtual_files.get_fd_detail(fd)
        if not detail: return -1

        try:
            stats = os.fstat(fd)
            uid = self.__fs_helpers._get_config_uid(detail.name)
            st_mode = self.__fs_helpers._fix_st_mode(detail.name, stats.st_mode)

            if self.__emu.arch == emu_const.ARCH_ARM32:
                file_helpers.stat_to_memory2(mu, stat_ptr, stats, uid, st_mode, self.__emu.config)

            else:
                file_helpers.stat_to_memory64(mu, stat_ptr, stats, uid, st_mode, self.__emu.config)

            return 0
        except OSError: return -1

    def _getdents64(self, mu, fd, linux_dirent64_ptr, count):
        entry = self.__pcb.virtual_files.get_fd_detail(fd)
        if not entry:
            return -1  # EBADF

        if hasattr(entry, 'offset') and entry.offset > 0:
            return 0

        is_dir, content = self.__generator.prepare_path(entry.name, entry.name_in_system, fd=fd)
        if not is_dir or content is None:
            return 0

        if isinstance(content, bytes):
            mu.mem_write(linux_dirent64_ptr, content[:count])
            entry.offset = len(content)
            return len(content[:count])
        
        entry.offset = count
        return count

    def _statfs64(self, mu, path_ptr, sz, buf):        
        path = memory_helpers.read_utf8(mu, path_ptr)
        logging.debug("statfs64 path %s"%path)
        path = self.__fs_helpers._translate_path(path)
        if (not os.path.exists(path)):
            return -1
        #
        statv = os.statvfs(path)
        '''
        f_type = {uint32_t} 61267
        f_bsize = {uint32_t} 4096
        f_blocks = {uint64_t} 3290543
        f_bfree = {uint64_t} 2499155
        f_bavail = {uint64_t} 2499155
        f_files = {uint64_t} 838832
        f_ffree = {uint64_t} 828427
        f_fsid = {fsid_t} 
            __val = {int [2]} 
        f_namelen = {uint32_t} 255
        f_frsize = {uint32_t} 4096
        f_flags = {uint32_t} 1062
        f_spare = {uint32_t [4]} 
        '''
        f_fsid = 0
        if (hasattr(statv, "f_fsid")):
            print(statv)
            f_fsid = statv.f_fsid
        #
        if (self.__emu.arch == emu_const.ARCH_ARM32):
            mu.mem_write(buf, int(0xef53).to_bytes(4, 'little'))
            mu.mem_write(buf+4, int(statv.f_bsize).to_bytes(4, 'little'))
            mu.mem_write(buf+8, int(statv.f_blocks).to_bytes(8, 'little'))
            mu.mem_write(buf+16, int(statv.f_bfree).to_bytes(8, 'little'))
            mu.mem_write(buf+24, int(statv.f_bavail).to_bytes(8, 'little'))
            mu.mem_write(buf+32, int(statv.f_files).to_bytes(8, 'little'))
            mu.mem_write(buf+40, int(statv.f_ffree).to_bytes(8, 'little'))
            mu.mem_write(buf+48, int(f_fsid).to_bytes(8, 'little'))
            mu.mem_write(buf+56, int(statv.f_namemax).to_bytes(4, 'little'))
            mu.mem_write(buf+60, int(statv.f_frsize).to_bytes(4, 'little'))
            mu.mem_write(buf+64, int(statv.f_flag).to_bytes(4, 'little'))
            mu.mem_write(buf+68, int(0).to_bytes(16, 'little'))
        else:
            #arm64
            mu.mem_write(buf, int(0xef53).to_bytes(8, 'little'))
            mu.mem_write(buf+8, int(statv.f_bsize).to_bytes(8, 'little'))
            mu.mem_write(buf+16, int(statv.f_blocks).to_bytes(8, 'little'))
            mu.mem_write(buf+24, int(statv.f_bfree).to_bytes(8, 'little'))
            mu.mem_write(buf+32, int(statv.f_bavail).to_bytes(8, 'little'))
            mu.mem_write(buf+40, int(statv.f_files).to_bytes(8, 'little'))
            mu.mem_write(buf+48, int(statv.f_ffree).to_bytes(8, 'little'))
            mu.mem_write(buf+56, int(f_fsid).to_bytes(8, 'little'))
            mu.mem_write(buf+64, int(statv.f_namemax).to_bytes(8, 'little'))
            mu.mem_write(buf+72, int(statv.f_frsize).to_bytes(8, 'little'))
            mu.mem_write(buf+80, int(statv.f_flag).to_bytes(8, 'little'))
            mu.mem_write(buf+88, int(0).to_bytes(32, 'little'))

        return 0


    def _access(self, mu, filename_ptr, flags):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        is_virtual, _ = self.__generator.prepare_path(filename, "")

        if is_virtual:
            logging.debug("access '%s' (virtual) -> 0", filename)
            return 0
        
        vfs_path = self.__fs_helpers._translate_path(filename)
        rc = os.access(vfs_path, flags)
        r = -1
        if (rc):
            r = 0
    
        logging.debug("access '%s' return %d" %(filename, r))
        return r
    
    def _mkdir(self, mu, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)
        vfs_path = self.__fs_helpers._translate_path(path)

        logging.debug("mkdir call path [%s]"%path)
        if (not os.path.exists(vfs_path)):
            os.makedirs(vfs_path)
        return 0

    def _mkdirat(self, mu, dfd, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)

        path = self.__fs_helpers._dirfd_2_path(dfd, path)
        if (path == None):
            return -1

        vfs_path = self.__fs_helpers._translate_path(path)

        logging.debug("mkdirat call path [%s]"%path)
        if (not os.path.exists(vfs_path)):
            os.makedirs(vfs_path)

        return 0

    def _unlinkat(self, mu, dfd, path_ptr, flag):
        path = memory_helpers.read_utf8(mu, path_ptr)
        logging.debug("unlinkat call dfd [%d] path [%s]"%(dfd, path))

        path = self.__fs_helpers._dirfd_2_path(dfd, path)
        if (path == None):
            return -1
        vfs_path = self.__fs_helpers._translate_path(path)
        #TODO delete real file

    def _readlinkat(self, mu, dfd, path, buf, bufsz):
        path_utf8 = memory_helpers.read_utf8(mu, path)
        logging.debug("readed linkat dfd %x path %s buf %x bufsz %r", dfd, path_utf8, buf, bufsz)
        path_utf8 =  self.__fs_helpers._dirfd_2_path(dfd, path_utf8)
        if (path_utf8 == None):
            return -1

        pobj = self.__pcb
        pid = pobj.pid

        path_std_utf = path_utf8.replace(str(pid), "self")
        fd_base = "/proc/self/fd/"

        if (path_std_utf.startswith(fd_base)):
            
            fd_str = os.path.basename(path_std_utf)
            fd = int(fd_str)
            detail = self.__pcb.virtual_files.get_fd_detail(fd)
            name = detail.name
            n = len(name)

            if (n <= bufsz):
                memory_helpers.write_utf8(mu, buf, name)
                return 0

            else:
                raise RuntimeError("buffer overflow!!!")

        else:
            raise NotImplementedError()

        return -1

    def _faccessat(self, mu, dirfd, pathname_ptr, mode, flag):
        filename = memory_helpers.read_utf8(mu, pathname_ptr)
        logging.debug("faccessat filename:[%s]"%filename)
        filename = self.__fs_helpers._dirfd_2_path(dirfd, filename)
        if (filename == None):
            return -1

        name_in_host = self.__fs_helpers._translate_path(filename)
        if (os.access(name_in_host, mode)):
            return 0
        else:
            logging.debug("faccessat filename:[%s] not exist"%filename)
            return -1