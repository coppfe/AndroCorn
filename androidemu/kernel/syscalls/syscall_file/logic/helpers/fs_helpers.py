import os
import ctypes
import logging
import shutil
import platform

from ......objects.vdstat import VirtualDeviceStat

from ......utils.files import file_helpers
from ......const import emu_const
from ......const import linux

from ......utils import misc_utils

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ......emulator import Emulator
    from ......objects.virtual_file import VirtualFile
    from ......pcb import Pcb
    from ......utils.generators.vfs_content import ContentGenerator

class FSHelpers:

    def __init__(self, emulator: 'Emulator', content_generator: 'ContentGenerator', root_path: str):
        self.__emu: 'Emulator' = emulator
        self.__pcb: 'Pcb' = emulator.pcb

        self.__generator: 'ContentGenerator' = content_generator

        self.__root_list = set(["/dev/__properties__"])
        self.__root_path = root_path

        self.g_isWin = platform.system() == "Windows"
    
    def _get_path_owners(self, filename_in_vm):
        filename_norm = self._norm_file_name(filename_in_vm)
        if filename_norm.startswith(("/system", "/vendor", "/dev", "/proc")):
            return 0, 0
        uid = self.__emu.config.pkg.uid
        return uid, uid
    
    def _make_stat_object(self, filename, vfile=None, follow_links=True):
        uid, gid = self._get_path_owners(filename)
        tm = self.__emu.time_manager
        
        is_virtual_dev = self.__generator.is_virtual(filename)
        if is_virtual_dev:
            if "random" in filename: major, minor = 1, 8
            elif "null" in filename: major, minor = 1, 3
            elif "zero" in filename: major, minor = 1, 5
            else: major, minor = 10, 200
            return VirtualDeviceStat.create_char_device(major, minor, tm, uid, gid)
        
        if not vfile:
            vfile = self.__pcb.virtual_files.get_fd_by_name(filename)

        if vfile:
            vfile = cast("VirtualFile", vfile)
            return VirtualDeviceStat.create_regular_file(
                size=vfile.get_size(),
                time_manager=tm,
                uid=uid, gid=gid,
                st_ino=vfile.descriptor
            )

        try:
            if vfile and not vfile.is_virtual:
                host_stat = os.fstat(vfile.descriptor)
            else:
                file_path = self._translate_path(filename)
                host_stat = os.stat(file_path) if follow_links else os.lstat(file_path)

            return VirtualDeviceStat(
                st_mode=self._fix_st_mode(filename, host_stat.st_mode),
                st_size=host_stat.st_size,
                st_ino=host_stat.st_ino,
                st_dev=host_stat.st_dev,
                st_uid=uid,
                st_gid=gid,
                time_manager=tm
            )
        except OSError:
            return None
        
    def _internal_path_stat_handler(self, mu, filename, buf_ptr, follow_links=True):
        stats = self._make_stat_object(filename, follow_links=follow_links)
        if not stats: return -linux.EPERM

        is_arm32 = self.__emu.arch == emu_const.ARCH_ARM32
        write_func = file_helpers.stat_to_memory2 if is_arm32 else file_helpers.stat_to_memory64
        write_func(mu, buf_ptr, stats, stats.st_uid, stats.st_mode, self.__emu.config)
        return 0

    def _clear_proc_dir(self):
        return 0
        proc = "/proc"
        proc = self._translate_path(proc)
        dirs = os.listdir(proc)
        for d in dirs:
            if (d.isdigit()):
                fp = "%s/%s/"%(proc, d)
                shutil.rmtree(fp)

    def _translate_path(self, filename):
        return misc_utils.vfs_path_to_system_path(self.__root_path, filename)

    def _dirfd_2_path(self, dirfd, relpath) -> str:
        dirfd_signed = ctypes.c_int32(dirfd).value

        if dirfd_signed == linux.AT_FDCWD:
            return relpath

        if os.path.isabs(relpath):
            return relpath
        
        fdesc = self.__pcb.virtual_files.get_fd_detail(dirfd_signed)
        if fdesc is None:
            logging.info("dirfd %d is invalid!!! (original: %d)", dirfd_signed, dirfd)
            return None

        dirpath = fdesc.name
        path = os.path.join(dirpath, relpath)
        return path
    
    def _get_config_uid(self, filename_in_vm):
        filename_norm = self._norm_file_name(filename_in_vm)
        uid = 0
        # Note that in Linux C, opening /dev/__properties__ requires root access. If the user is not root, initialization will fail and the system will crash.
        # It will also crash if other groups or users in the same group have writable access!
        if (filename_norm in self.__root_list):
            uid = 0

        else:
            uid = self.__emu.config.pkg.uid
        return uid
    
    def _norm_file_name(self, filename_in_vm):
        filename_norm = os.path.normpath(filename_in_vm)
        if (self.g_isWin):
            # Windows paths use backslashes after standardization; we'll replace them with Linux forward slashes here.
            filename_norm = filename_norm.replace("\\", "/")

        return filename_norm

    def _fix_st_mode(self, filename_in_vm, st_mode):
        filename_norm = self._norm_file_name(filename_in_vm)
        # Note that in Linux C, opening /dev/__properties__ requires root access. If the user is not root, initialization will fail and the system will crash.
        # It will also crash if other groups or users in the same group have writable access!
        if (filename_norm in self.__root_list):
            # Other groups and the current group are not writable within the root directory.
            st_mode = st_mode & (~0o0000020) #S_IWGRP
            st_mode = st_mode & (~0o0000002) #S_IWOTH

        return st_mode
    
    def _del_fd_link(self, fd):
        if (self.g_isWin):
            # TODO?
            return 

        if (fd >= 0):
            pid = self.__pcb.pid
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self._translate_path(fdbase)
            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)