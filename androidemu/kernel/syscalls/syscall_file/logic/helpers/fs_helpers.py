import os
import ctypes
import logging
import shutil
import platform

from .structs.vdstat import VirtualDeviceStat

from ......utils.files import file_helpers
from ......const import emu_const
from ......const import linux

from ......utils import misc_utils

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ......emulator import Emulator
    from .....pcb import Pcb
    from ......utils.generators.vfs_content import ContentGenerator

class FSHelpers:

    def __init__(self, emulator: 'Emulator', content_generator: 'ContentGenerator', root_path: str):
        self.__emu: 'Emulator' = emulator
        self.__pcb: 'Pcb' = emulator.pcb

        self.__generator: 'ContentGenerator' = content_generator

        self.__root_list = set(["/dev/__properties__"])
        self.__root_path = root_path

        self.g_isWin = platform.system() == "Windows"
        
    def _internal_path_stat_handler(self, mu, filename, buf_ptr, follow_links=True):
        is_virtual, _ = self.__generator.prepare_path(filename, "", ignore_handler=True)
        uid = self._get_config_uid(filename)

        if is_virtual:
            fd = self.__pcb.virtual_files.add_virtual_fd(filename, filename)
            stats = VirtualDeviceStat(fd, filename, self.__emu.time_manager)
            st_mode = stats.st_mode
        else:
            file_path = self._translate_path(filename)
            try:
                stats = os.stat(file_path) if follow_links else os.lstat(file_path)
                st_mode = self._fix_st_mode(filename, stats.st_mode)
            except OSError:
                return -1

        is_arm32 = self.__emu.arch == emu_const.ARCH_ARM32
        write_func = file_helpers.stat_to_memory2 if is_arm32 else file_helpers.stat_to_memory64
        
        write_func(mu, buf_ptr, stats, uid, st_mode, self.__emu.config)
        
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
            logging.info(f"dirfd {dirfd_signed} is invalid!!! (original: {dirfd})")
            return None

        dirpath = fdesc.name
        path = os.path.join(dirpath, relpath)
        print(f"[*] dirfd_2_path({dirfd_signed}, {relpath}) => {path}")
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