import os
import ctypes
import logging
import zlib

from .....objects.vdstat import VirtualDeviceStat

from .....utils.files import helpers
from .....const import emu_const
from .....const import linux

from .....utils import misc_utils
from .....utils.files.modemap import FileModeMap

from .....types.alias import _os

from typing import TYPE_CHECKING, Set, List

if TYPE_CHECKING:
    from .....objects.virtual_file import VirtualFile
    from .....core.process.pcb import ProcessControlBlock
    from ....dev.content import ContentGenerator
    from androidemu.data.config import Config
    from androidemu.core.state.time_manager import TimeManager
    from unicorn import Uc
    from androidemu.core.state._global import GlobalContextMachine

class FileSystemUtils:

    def __init__(self, pcb: 'ProcessControlBlock', config: 'Config', content_generator: 'ContentGenerator', time_manager: 'TimeManager', ctx: 'GlobalContextMachine', root_path: str):
        self._pcb = pcb
        self._ctx = ctx
        self._config = config
        self._time_manager = time_manager

        self._generator: 'ContentGenerator' = content_generator

        self._root_list: Set[List[str]] = set(["/dev/__properties__"])
        self._root_path: str = root_path

        self.g_isWin: bool = _os == "Windows"

    def _get_path_owners(self, filename_in_vm):
        filename_norm = self._norm_file_name(filename_in_vm)
        if filename_norm.startswith(("/system", "/vendor", "/dev", "/proc")):
            return 0, 0
        uid = self._config.pkg.uid
        return uid, uid

    def _make_stat_object(self, vfile: 'VirtualFile', follow_links: bool = True):
        filename = vfile.name
        uid, gid = self._get_path_owners(filename)
        tm = self._time_manager

        st_dev = FileModeMap.get_st_dev(filename)
        st_rdev = FileModeMap.get_st_rdev(filename)

        st_ino = zlib.adler32(filename.encode()) & 0xFFFFFFFF

        if st_rdev != 0:
            major = st_rdev >> 8
            minor = st_rdev & 0xFF
            return VirtualDeviceStat.create_char_device(
                major, minor, tm, uid, gid,
                st_dev=st_dev,
                st_ino=st_ino
            )

        if vfile.is_virtual:
            is_proc_or_sys = filename.startswith("/proc") or filename.startswith("/sys")
            size = 0 if is_proc_or_sys else vfile.get_size()

            is_dir = getattr(vfile, 'is_directory', False)
            nlink = 2 if is_dir else 1

            if "/proc" in filename and "fd" in filename:
                 nlink = 2 + len(self._pcb.virtual_files.get_all_fds())
            
            if "__properties__" in filename:
                return VirtualDeviceStat.create_char_device(
                    st_ino=st_ino,
                    st_dev=st_dev,
                    st_uid=uid,
                    st_gid=gid,
                    st_nlink=nlink,
                    time_manager=tm
                )

            return VirtualDeviceStat(
                st_mode=vfile.mode if hasattr(vfile, 'mode') else (0o100444 if not is_dir else 0o40555),
                st_size=size,
                st_ino=st_ino,
                st_dev=st_dev,
                st_uid=uid,
                st_gid=gid,
                st_nlink=nlink,
                time_manager=tm
            )

        try:
            file_path = self._translate_path(filename)
            host_stat = os.stat(file_path) if follow_links else os.lstat(file_path)

            return VirtualDeviceStat(
                st_mode=self._fix_st_mode(filename, host_stat.st_mode),
                st_size=host_stat.st_size,
                st_ino=st_ino,
                st_dev=st_dev,
                st_uid=uid,
                st_gid=gid,
                st_nlink=host_stat.st_nlink,
                time_manager=tm
            )
        except OSError as e:
            logging.error("Stat failed for non-existent path %s: %s", filename, e)
            return None

    def _internal_path_stat_handler(self, mu: 'Uc', filename, buf_ptr, follow_links: bool = True):
        filename = self._norm_file_name(filename)

        fd = self._pcb.virtual_files.get_fd_by_name(filename)
        vfile = self._pcb.virtual_files.get_fd_detail(fd)

        if not vfile:
            is_virtual = self._generator.is_virtual(filename)
            vfile = self._pcb.virtual_files.create_virtual_file(filename, filename, -1, is_virtual)

        stats = self._make_stat_object(vfile=vfile, follow_links=follow_links)

        if not stats:
            return -linux.ENOENT

        is_arm32 = mu._arch == emu_const.ARCH_ARM32
        write_func = helpers.stat_to_memory2 if is_arm32 else helpers.stat_to_memory64
        write_func(mu, buf_ptr, stats)
        return 0

    def _clear_proc_dir(self):
        return 0
        # proc = "/proc"
        # proc = self._translate_path(proc)
        # dirs = os.listdir(proc)
        # for d in dirs:
        #     if (d.isdigit()):
        #         fp = "%s/%s/"%(proc, d)
        #         shutil.rmtree(fp)

    def _translate_path(self, filename):
        return misc_utils.vfs_path_to_system_path(self._root_path, filename)

    def _dirfd_2_path(self, dirfd, relpath) -> str:
        dirfd_signed = ctypes.c_int32(dirfd).value

        if dirfd_signed == linux.AT_FDCWD:
            return relpath

        if os.path.isabs(relpath):
            return relpath

        fdesc = self._pcb.virtual_files.get_fd_detail(dirfd_signed)
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
        if (filename_norm in self._root_list):
            uid = 0

        else:
            uid = self._config.pkg.uid
        return uid

    def _norm_file_name(self, filename_in_vm):
        filename_norm = os.path.normpath(filename_in_vm)

        if self.g_isWin:
            filename_norm = filename_norm.replace("\\", "/")

        if filename_norm.startswith(self._root_path+"/"):
            filename_norm = filename_norm[3:]
        if filename_norm.startswith("/"+self._root_path+"/"):
            filename_norm = filename_norm[4:]

        if not filename_norm.startswith("/"):
            filename_norm = "/" + filename_norm

        return filename_norm

    def _fix_st_mode(self, filename_in_vm, st_mode):
        filename_norm = self._norm_file_name(filename_in_vm)
        # Note that in Linux C, opening /dev/__properties__ requires root access. If the user is not root, initialization will fail and the system will crash.
        # It will also crash if other groups or users in the same group have writable access!
        if (filename_norm in self._root_list):
            # Other groups and the current group are not writable within the root directory.
            st_mode = st_mode & (~0o0000020) #S_IWGRP
            st_mode = st_mode & (~0o0000002) #S_IWOTH

        return st_mode

    def _del_fd_link(self, fd):
        if (self.g_isWin):
            # TODO?
            return

        if (fd >= 0):
            pid = self._ctx.pid
            fdbase = "/proc/%d/fd/"%pid
            fdbase = self._translate_path(fdbase)
            p = "%s/%d"%(fdbase, fd)
            if (os.path.exists(p)):
                os.remove(p)
