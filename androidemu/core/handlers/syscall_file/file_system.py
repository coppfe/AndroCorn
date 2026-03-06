import logging
import os

from ....utils.memory import memory_helpers

from ....const.linux import *
from ....utils import misc_utils
from ....const import emu_const
from . import file_helpers
from ....const import linux
from ....utils.generators.vfs_generators import VFSGenerator
from .device_stat import VirtualDeviceStat


import platform
import shutil
import select

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ....emulator import Emulator
    from ....core.handlers.syscall_base.syscall_handlers import SyscallHandlers
    from ....config import Config
    from ....utils.memory.memory_map import MemoryMap

g_isWin = platform.system() == "Windows"
if not g_isWin:
    import fcntl
#

class VirtualFileSystem:

    def __translate_path(self, filename):
        return misc_utils.vfs_path_to_system_path(self._root_path, filename)
    #

    def __clear_proc_dir(self):
        proc = "/proc"
        proc = self.__translate_path(proc)
        dirs = os.listdir(proc)
        for d in dirs:
            if (d.isdigit()):
                fp = "%s/%s/"%(proc, d)
                shutil.rmtree(fp)
            #
        #
    #

    """
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, emu: 'Emulator', root_path: str, cfg: 'Config', syscall_handler: 'SyscallHandlers', memory_map: 'MemoryMap'):
        self.__emu = emu
        self._root_path = root_path
        self.__cfg = cfg
        self.__memory_map = memory_map
        self.__pcb = emu.pcb


        # Utils
        self.__generator = VFSGenerator(cfg, self.__pcb, memory_map)

        # Fields
        self.__next_virtual_fd = 1000 
        self.__virtual_fd_map = {} # fd -> device_name

        self.__clear_proc_dir()
        self.__root_list = set(["/dev/__properties__"])
        if (self.__emu.arch == emu_const.ARCH_ARM32):
            syscall_handler.set_handler(0x3, "read", 3, self._handle_read)
            syscall_handler.set_handler(0x4, "write", 3, self._handle_write)
            syscall_handler.set_handler(0x5, "open", 3, self._handle_open)
            syscall_handler.set_handler(0x6, "close", 1, self._handle_close)
            syscall_handler.set_handler(0x0A, "unlink", 1, self._handle_unlink)
            syscall_handler.set_handler(0x13, "lseek", 3, self._handle_lseek)
            syscall_handler.set_handler(0x21, "access", 2, self._handle_access)
            syscall_handler.set_handler(0x27, "mkdir", 2, self.__mkdir)
            syscall_handler.set_handler(0x36, "ioctl", 6, self.__ioctl)
            syscall_handler.set_handler(0x37, "fcntl", 6, self.__fcntl64)
            syscall_handler.set_handler(0x6C, "fstat", 2, self._handle_fstat64)
            syscall_handler.set_handler(0x8c, "_llseek", 5, self._handle_llseek)
            syscall_handler.set_handler(0x92, "writev", 3, self._handle_writev)
            syscall_handler.set_handler(0xA8, "poll", 3, self._handle_poll)
            syscall_handler.set_handler(0xC3, "stat64", 2, self._handle_stat64)
            syscall_handler.set_handler(0xC4, "lstat64", 2, self._handle_lstat64)
            syscall_handler.set_handler(0xC5, "fstat64", 2, self._handle_fstat64)
            syscall_handler.set_handler(0xD9, "getdents64", 3, self._handle_getdents64)
            syscall_handler.set_handler(0xDD, "fcntl64", 6, self.__fcntl64)
            syscall_handler.set_handler(0x10A, "statfs64", 3, self.__statfs64)
            syscall_handler.set_handler(0x142, "openat", 4, self._handle_openat)
            syscall_handler.set_handler(0x143, "mkdirat", 3, self.__mkdirat)
            syscall_handler.set_handler(0x147, "fstatat64", 4, self._handle_fstatat64)
            syscall_handler.set_handler(0x148, "unlinkat", 3, self.__unlinkat)
            syscall_handler.set_handler(0x14c, "readlinkat", 4, self.__readlinkat)
            syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
            syscall_handler.set_handler(0x150, "ppoll", 4, self.__ppoll)

        else:
            #arm64
            syscall_handler.set_handler(0x3f, "read", 3, self._handle_read)
            syscall_handler.set_handler(0x40, "write", 3, self._handle_write)
            #no open syscall in arm64
            syscall_handler.set_handler(0x39, "close", 1, self._handle_close)
            #no unlink syscall
            syscall_handler.set_handler(0x3e, "lseek", 3, self._handle_lseek)
            #no access syscall
            #no mkdir
            syscall_handler.set_handler(0x1d, "ioctl", 6, self.__ioctl)
            syscall_handler.set_handler(0x19, "fcntl", 6, self.__fcntl64)
            syscall_handler.set_handler(0x50, "fstat", 2, self._handle_fstat64)

            #no _lllseek
            syscall_handler.set_handler(0x42, "writev", 3, self._handle_writev)
            #no poll
            #no stat64
            #no lstat64
            #no fstat64 use fstat
            syscall_handler.set_handler(0x3D, "getdents64", 3, self._handle_getdents64)
            #no fcntl64
            #no statfs64

            syscall_handler.set_handler(0x2B, "statfs", 3, self.__statfs64)
            syscall_handler.set_handler(0x38, "openat", 4, self._handle_openat)
            syscall_handler.set_handler(0x22, "mkdirat", 3, self.__mkdirat)
            #no fstatat64

            syscall_handler.set_handler(0x23, "unlinkat", 3, self.__unlinkat)
            syscall_handler.set_handler(0x4E, "readlinkat", 4, self.__readlinkat)
            syscall_handler.set_handler(0x30, "faccessat", 4, self._faccessat)
            syscall_handler.set_handler(0x49, "ppoll", 4, self.__ppoll)

            syscall_handler.set_handler(0x4F, "newfstatat", 4, self._handle_fstatat64)

        #

    #

    def __create_fd_link(self, fd, target):
        global g_isWin
        if (g_isWin):
            return
        #
        if (fd >= 0):
            pid = self.__pcb.get_pid()
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self.__translate_path(fdbase)
            if (not os.path.exists(fdbase)):
                os.makedirs(fdbase)
            #
            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)
            #
            full_target = os.path.abspath(target)
            os.symlink(full_target, p, False)
        #
    #

    def __del_fd_link(self, fd):
        global g_isWin
        if (g_isWin):
            return
        #
        if (fd >= 0):
            pid = self.__pcb.get_pid()
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self.__translate_path(fdbase)
            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)
            #
        #
    #

    def _open_file(self, filename, oflag):
        file_path = self.__translate_path(filename)

        is_virtual, path_info = self.__generator.prepare_path(filename, file_path)

        if is_virtual:
            dev_name = path_info
            
            vfd = self.__next_virtual_fd
            self.__next_virtual_fd += 1
            
            self.__virtual_fd_map[vfd] = dev_name
            
            self.__pcb.add_fd(filename, f"VIRTUAL:{dev_name}", vfd)
            
            logging.info(f"Opened VIRTUAL device {filename} as fd {vfd}")
            return vfd

        real_host_path = path_info

        if real_host_path and os.path.exists(real_host_path):
            if (oflag & 0o00000001):
                flags = os.O_RDWR if g_isWin else os.O_WRONLY
            elif (oflag & 0o00000002):
                flags = os.O_RDWR
            else:
                flags = os.O_RDONLY
            
            if (oflag & 0o100):
                flags |= os.O_CREAT
            if (oflag & 0o2000):
                flags |= os.O_APPEND
            if (oflag & 0o40000):
                flags |= os.O_DIRECTORY
            if (oflag & 0o010000000):
                flags |= os.O_PATH
            
            fd = misc_utils.my_open(file_path, flags)
            
            self.__pcb.add_fd(filename, file_path, fd)
            logging.info("open [%s][0x%x] return fd %d" % (file_path, oflag, fd))
            
            self.__create_fd_link(fd, file_path)
            
            return fd
        else:
            logging.warning("File does not exist '%s'" % filename)
            return -1

    def __dirfd_2_path(self, dirfd, relpath):
        if (dirfd == linux.AT_FDCWD):
            return relpath
        #
        if (os.path.isabs(relpath)):
            #绝对路径，直接忽略
            return relpath
        #
        else:
            fdesc = self.__pcb.get_fd_detail(dirfd)
            if (fdesc == None):
                #fd不存在，可能是bug...要看被模拟的程序逻辑
                logging.info("dirfd %d is invalid!!!"%dirfd)
                return None
            #
            dirpath = fdesc.name
            path = os.path.join(dirpath, relpath)
            return path
        #
    #

    def __norm_file_name(self, filename_in_vm):
        filename_norm = os.path.normpath(filename_in_vm)
        global g_isWin
        if (g_isWin):
            #windows的路径标准化之后是反斜杠的，这里换成linux的正斜杠
            filename_norm = filename_norm.replace("\\", "/")
        #
        return filename_norm
    #

    def __get_config_uid(self, filename_in_vm):
        filename_norm = self.__norm_file_name(filename_in_vm)
        uid = 0
        #注意linux c打开/dev/__properties__检测是不是root，如果不是root初始化失败而崩溃,如果其他组或者本组用户可写也会崩溃！！！
        if (filename_norm in self.__root_list):
            uid = 0
        #
        else:
            uid = self.__cfg.get("uid")
        return uid
    #

    def __fix_st_mode(self, filename_in_vm, st_mode):
        filename_norm = self.__norm_file_name(filename_in_vm)
        #注意linux c打开/dev/__properties__检测是不是root，如果不是root初始化失败而崩溃,如果其他组或者本组用户可写也会崩溃！！！
        if (filename_norm in self.__root_list):
            #在root里面其他组和本组不可写
            st_mode = st_mode & (~0o0000020) #S_IWGRP
            st_mode = st_mode & (~0o0000002) #S_IWOTH
        #
        return st_mode
    #

    def _handle_read(self, mu, fd, buf_addr, count):
        if fd in self.__virtual_fd_map:
            dev_name = self.__virtual_fd_map[fd]
            data = b""
            
            if dev_name in ["/dev/urandom", "/dev/random"]:
                data = os.urandom(count)
                
            elif dev_name == "/dev/null":
                data = b""
                
            else:
                logging.warning(f"Read from unimplemented virtual device {dev_name}")
            
            if len(data) > 0:
                mu.mem_write(buf_addr, data)
            
            logging.debug(f"VIRTUAL READ fd={fd} ({dev_name}) count={count} ret={len(data)}")
            return len(data)

        if fd <= 2: 
            return 0 

        try:
            buf = os.read(fd, count)
            mu.mem_write(buf_addr, buf)
            return len(buf)
        except OSError as e:
            logging.error(f"Read error on fd {fd}: {e}")
            return -1

    def _handle_write(self, mu, fd, buf_addr, count):
        
        data = mu.mem_read(buf_addr, count)
        if (fd == 1):
            s = bytes(data).decode("utf-8")
            logging.debug("stdout:[%s]"%s)
            return len(data)
        elif(fd == 2):
            s = bytes(data).decode("utf-8")
            logging.warning("stderr:[%s]"%s)
            return len(data)
        #

        try:
            r = os.write(fd, data)
        except OSError as e:
            file = self.__pcb.get_fd_detail(fd)
            logging.warning("File write '%s' error %r skip" %(file.name, e))
            return -1
        #
        return r
    #

    def _handle_open(self, mu, filename_ptr, flags, mode):
        """
        int open(const char *pathname, int flags, mode_t mode);

        return the new file descriptor, or -1 if an error occurred (in which case, errno is set appropriately).
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        return self._open_file(filename, flags)

    def _handle_close(self, mu, fd):
        """
        int close(int fd);

        close() closes a file descriptor, so that it no longer refers to any file and may be reused. Any record locks
        (see fcntl(2)) held on the file it was associated with, and owned by the process, are removed (regardless of
        the file descriptor that was used to obtain the lock).

        close() returns zero on success. On error, -1 is returned, and errno is set appropriately.
        """

        if fd in self.__virtual_fd_map:
            del self.__virtual_fd_map[fd]
            self.__pcb.remove_fd(fd)
            return 0

        try:
            if (self.__pcb.has_fd(fd)):
                self.__pcb.remove_fd(fd)
                os.close(fd)
                self.__del_fd_link(fd)
            else:
                #之前关闭过的直接返回0,与安卓系统行为一致
                logging.warning("fd 0x%08X not in fds maybe has closed, just return 0"%fd)
                return 0
        except OSError as e:
            logging.warning("fd %d close error."%fd)
            return -1
        #
        return 0
    
    def _handle_unlink(self, mu, path_ptr):
        path = memory_helpers.read_utf8(mu, path_ptr)
        vfs_path = self.__translate_path(path)
        logging.debug("unlink call path [%s]"%path)
        return 0
    #

    def _handle_lseek(self, mu, fd, offset, whence):
        return os.lseek(fd, offset, whence)
    #

    def _handle_access(self, mu, filename_ptr, flags):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        is_virtual, _ = self.__generator.prepare_path(filename, "")

        if is_virtual:
            logging.debug(f"access '{filename}' (virtual) -> 0")
            return 0
        
        vfs_path = self.__translate_path(filename)
        rc = os.access(vfs_path, flags)
        r = -1
        if (rc):
            r = 0
        #
        logging.debug("access '%s' return %d" %(filename, r))
        return r
    #
    def __mkdir(self, mu, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)
        vfs_path = self.__translate_path(path)

        logging.debug("mkdir call path [%s]"%path)
        if (not os.path.exists(vfs_path)):
            os.makedirs(vfs_path)
        #
        return 0
    #

    def _handle_writev(self, mu, fd, vec, vlen):
        n = 0
        ptr_sz = self.__emu.ptr_size
        vec_sz = 2*ptr_sz
        for i in range(0, vlen):
            addr = memory_helpers.read_ptr_sz(mu, vec + (i * vec_sz), ptr_sz)
            size = memory_helpers.read_ptr_sz(mu, vec + (i * vec_sz) + ptr_sz, ptr_sz)
            data = bytes(mu.mem_read(addr, size))
            logging.debug('Writev %r' % data)
            n += os.write(fd, data)
        #
        return n
    #

    def __do_poll(self, mu, pollfd_ptr, nfds, timeout):
        VIRT_READY = 0x0005 # POLLIN | POLLOUT
        poll_list = []
        p = select.poll() if hasattr(select, "poll") else None
        virtual_ready_count = 0
        
        for i in range(nfds):
            ptr = pollfd_ptr + (i * 8)
            fd = int.from_bytes(mu.mem_read(ptr, 4), 'little')
            events = int.from_bytes(mu.mem_read(ptr + 4, 2), 'little')
            
            is_virt = fd in self.__virtual_fd_map
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

    def _handle_poll(self, mu, pollfd_ptr, nfds, timeout):
        return self.__do_poll(mu, pollfd_ptr, nfds, timeout)
    #
    
    def __ppoll(self, mu, pollfd_ptr, nfds, timeout_ts_ptr, sigmask_ptr):
        timeout = -1
        if timeout_ts_ptr != 0:
            ptr_sz = self.__emu.ptr_size
            tv_sec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr, ptr_sz)
            tv_nsec = memory_helpers.read_ptr_sz(mu, timeout_ts_ptr + ptr_sz, ptr_sz)
            timeout = int(tv_sec * 1000 + tv_nsec / 1000000)
        #
        return self.__do_poll(mu, pollfd_ptr, nfds, timeout)
    #

    def _handle_stat64(self, mu, filename_ptr, buf_ptr):
        return self.__internal_path_stat_handler(mu, memory_helpers.read_utf8(mu, filename_ptr), buf_ptr, True)

    def _handle_lstat64(self, mu, filename_ptr, buf_ptr):
        return self.__internal_path_stat_handler(mu, memory_helpers.read_utf8(mu, filename_ptr), buf_ptr, False)

    def __internal_path_stat_handler(self, mu, filename, buf_ptr, follow_links=True):
        is_virtual, _ = self.__generator.prepare_path(filename, "")
        if is_virtual:
            vstat = VirtualDeviceStat(1000, filename, self.__emu.time_manager)
            uid = self.__get_config_uid(filename)
            if self.__emu.arch == emu_const.ARCH_ARM32:
                file_helpers.stat_to_memory2(mu, buf_ptr, vstat, uid, vstat.st_mode)
            else:
                file_helpers.stat_to_memory64(mu, buf_ptr, vstat, uid, vstat.st_mode)
            return 0

        file_path = self.__translate_path(filename)
        try:
            stats = os.stat(file_path) if follow_links else os.lstat(file_path)
            uid = self.__get_config_uid(filename)
            st_mode = self.__fix_st_mode(filename, stats.st_mode)
            if self.__emu.arch == emu_const.ARCH_ARM32:
                file_helpers.stat_to_memory2(mu, buf_ptr, stats, uid, st_mode)
            else:
                file_helpers.stat_to_memory64(mu, buf_ptr, stats, uid, st_mode)
            return 0
        except OSError: return -1

    def _handle_fstat64(self, mu, fd, stat_ptr):
        if fd in self.__virtual_fd_map:
            dev_name = self.__virtual_fd_map[fd]
            vstat = VirtualDeviceStat(fd, dev_name, self.__emu.time_manager)
            uid = self.__get_config_uid(dev_name)
            if self.__emu.arch == emu_const.ARCH_ARM32:
                file_helpers.stat_to_memory2(mu, stat_ptr, vstat, uid, vstat.st_mode)
            else:
                file_helpers.stat_to_memory64(mu, stat_ptr, vstat, uid, vstat.st_mode)
            return 0

        detail = self.__pcb.get_fd_detail(fd)
        if not detail: return -1
        try:
            stats = os.fstat(fd)
            uid = self.__get_config_uid(detail.name)
            st_mode = self.__fix_st_mode(detail.name, stats.st_mode)
            if self.__emu.arch == emu_const.ARCH_ARM32:
                file_helpers.stat_to_memory2(mu, stat_ptr, stats, uid, st_mode)
            else:
                file_helpers.stat_to_memory64(mu, stat_ptr, stats, uid, st_mode)
            return 0
        except OSError: return -1

    def _handle_getdents64(self, mu, fd, linux_dirent64_ptr, count):
        logging.warning("syscall _handle_getdents64 %u %u %u skip..."%(fd, linux_dirent64_ptr, count))
        return -1
    #

    def __ioctl(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        #http://man7.org/linux/man-pages/man2/ioctl_list.2.html
        #0x00008912   SIOCGIFCONF      struct ifconf *
        #TODO:ifconf struct is complex, implement it

        SIOCGIFCONF = 0x00008912
        TCGETS = 0x5401

        logging.info("ioctl: fd=%x cmd=%x arg1=%x" % (fd, cmd, arg1))

        if cmd == TCGETS:
            if fd == 1 or fd == 2:
                logging.info(f"ioctl TCGETS for fd {fd}, pretending it is a TTY!")                
                return 0
            else:
                return -25

        if cmd == SIOCGIFCONF:
            logging.info("warning ioctl SIOCGIFCONF to get net addrs not implemented return -1 and skip")
            return -1
            
        raise NotImplementedError(f"ioctl cmd 0x{cmd:x} not implemented")

    def __fcntl64(self, mu, fd, cmd, arg1, arg2, arg3, arg4):
        #fcntl is not support on windows
        global g_isWin
        if (g_isWin):
            return 0
        r = fcntl.fcntl(fd, cmd, arg1)
        return r
    #

    def _handle_llseek(self, mu, fd, offset_high, offset_low, result_ptr, whence):
        if (offset_high != 0):
            raise RuntimeError("_llseek offset_high %d>0 not implemented"%offset_high)
        #
        n = os.lseek(fd, offset_low, whence)
        r = -1
        if (n > 0xFFFFFFFF):
            raise RuntimeError("_llseek return > 32 bits not implemented!!!")
        if (n >= 0):
            r = 0
            rbytes = n.to_bytes(8, 'little')
            mu.mem_write(result_ptr, rbytes)
        #
        return r
    #

    def __statfs64(self, mu, path_ptr, sz, buf):        
        path = memory_helpers.read_utf8(mu, path_ptr)
        logging.debug("statfs64 path %s"%path)
        path = self.__translate_path(path)
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
        #
        #raise NotImplementedError()
        return 0
    #

    def _handle_openat(self, mu, dfd, filename_ptr, flags, mode):
        """
        int openat(int dirfd, const char *pathname, int flags, mode_t mode);

        On success, openat() returns a new file descriptor.
        On error, -1 is returned and errno is set to indicate the error.

        EBADF
            dirfd is not a valid file descriptor.
        ENOTDIR
            pathname is relative and dirfd is a file descriptor referring to a file other than a directory.
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        filepath = self.__dirfd_2_path(dfd, filename)
        if (filepath == None):
            return -1
        #
        return self._open_file(filepath, flags)
    #


    def __mkdirat(self, mu, dfd, path_ptr, mode):
        path = memory_helpers.read_utf8(mu, path_ptr)

        path = self.__dirfd_2_path(dfd, path)
        if (path == None):
            return -1
        #
        vfs_path = self.__translate_path(path)

        logging.debug("mkdirat call path [%s]"%path)
        if (not os.path.exists(vfs_path)):
            os.makedirs(vfs_path)
        #
        return 0

    #
    def _handle_fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        path = self.__dirfd_2_path(dirfd, memory_helpers.read_utf8(mu, pathname_ptr))
        if path is None: return -1
        follow = not (flags & 0x100) # AT_SYMLINK_NOFOLLOW
        return self.__internal_path_stat_handler(mu, path, buf, follow)

    def __unlinkat(self, mu, dfd, path_ptr, flag):
        path = memory_helpers.read_utf8(mu, path_ptr)
        logging.debug("unlinkat call dfd [%d] path [%s]"%(dfd, path))

        path = self.__dirfd_2_path(dfd, path)
        if (path == None):
            return -1
        #
        vfs_path = self.__translate_path(path)
        #TODO delete real file
    #

    def __readlinkat(self, mu, dfd, path, buf, bufsz):
        path_utf8 = memory_helpers.read_utf8(mu, path)
        logging.debug("%x %s %x %r"%(dfd, path_utf8, buf, bufsz))
        path_utf8 =  self.__dirfd_2_path(dfd, path_utf8)
        if (path_utf8 == None):
            return -1
        #
        pobj = self.__pcb
        pid = pobj.get_pid()
        path_std_utf = path_utf8.replace(str(pid), "self")
        fd_base = "/proc/self/fd/"
        if (path_std_utf.startswith(fd_base)):
            fd_str = os.path.basename(path_std_utf)
            fd = int(fd_str)
            detail = self.__pcb.get_fd_detail(fd)
            name = detail.name
            n = len(name)
            if (n <= bufsz):
                memory_helpers.write_utf8(mu, buf, name)
                return 0
            #
            else:
                raise RuntimeError("buffer overflow!!!")
            #
        else:
            raise NotImplementedError()
        #
        return -1
    #
    
    def _faccessat(self, mu, dirfd, pathname_ptr, mode, flag):
        filename = memory_helpers.read_utf8(mu, pathname_ptr)
        logging.debug("faccessat filename:[%s]"%filename)
        filename = self.__dirfd_2_path(dirfd, filename)
        if (filename == None):
            return -1
        #
        name_in_host = self.__translate_path(filename)
        if (os.access(name_in_host, mode)):
            return 0
        else:
            logging.debug("faccessat filename:[%s] not exist"%filename)
            return -1
        #
    #

#
