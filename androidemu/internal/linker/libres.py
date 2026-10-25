import os
from typing import TYPE_CHECKING, Optional

from ...const import emu_const
from ...utils import misc_utils

if TYPE_CHECKING:
    from ...core.emulator import Emulator
    from ...utils.parsers.elf import ELFReader


class LibraryResolver:

    def __init__(self, emu: 'Emulator', vfs_root: str):
        self.emu = emu
        self.vfs_root = vfs_root
        self.is_64 = (emu.arch == emu_const.ARCH_ARM64)
        self.lib_dir = "lib64" if self.is_64 else "lib"
        self.abi_marker = "arm64-v8a" if self.is_64 else "armeabi-v7a"

    def resolve(self, filename: str) -> Optional[str]:
        if os.path.exists(filename):
            return filename

        base = os.path.basename(filename)
        pkg_name = self.emu.config.pkg.pkg_name

        search_paths = [
            f"/system/{self.lib_dir}/{base}",
            f"/vendor/{self.lib_dir}/{base}",
            f"/data/app/{pkg_name}/lib/{self.abi_marker}/{base}"
        ]

        for p in search_paths:
            real_path = misc_utils.vfs_path_to_system_path(self.vfs_root, p)
            if os.path.exists(real_path):
                return real_path

        return None

    def find_so_on_disk(self, so_path: str) -> Optional[str]:
        if os.path.isabs(so_path):
            return misc_utils.vfs_path_to_system_path(self.vfs_root, so_path)

        ld_dirs = ["/system/lib64/"] if self.is_64 else ["/system/lib/"]
        for lib_dir in ld_dirs:
            full_path = misc_utils.vfs_path_to_system_path(self.vfs_root, f"{lib_dir}{so_path}")
            if os.path.exists(full_path):
                return full_path

        return None

    def check_arch(self, reader: 'ELFReader', path: str) -> None:
        is_32 = reader.is_32
        emu_32 = (self.emu.arch == emu_const.ARCH_ARM32)
        if is_32 != emu_32:
            raise RuntimeError(f"Arch mismatch: {path}. Expected {'ARM32' if emu_32 else 'ARM64'}")