import posixpath
from typing import List, Optional
from ..selinux.policy import SELinuxPolicy


class MountPoint:
    def __init__(
        self,
        prefix: str,
        dev: int,
        default_uid: int = 0,
        default_gid: int = 0,
        file_mode: int = 0o100644,
        dir_mode: int = 0o040755,
        selinux_context: bytes = b"u:object_r:unlabeled:s0\x00"
    ):
        self.prefix = posixpath.normpath(prefix)
        if not self.prefix.startswith("/"):
            self.prefix = "/" + self.prefix
        if self.prefix != "/":
            self.prefix = self.prefix.rstrip("/")

        self.dev = dev
        self.default_uid = default_uid
        self.default_gid = default_gid
        self.file_mode = file_mode
        self.dir_mode = dir_mode
        self.selinux_context = selinux_context

    def matches(self, virt_path: str) -> bool:
        if self.prefix == "/":
            return True
        return virt_path == self.prefix or virt_path.startswith(self.prefix + "/")


class MountTable:
    def __init__(self, mount_points: Optional[List[MountPoint]] = None):
        self._mount_points: List[MountPoint] = []
        if mount_points:
            for mp in mount_points:
                self.add_mount(mp)

    def add_mount(self, mount_point: MountPoint) -> None:
        self._mount_points.append(mount_point)
        self._mount_points.sort(key=lambda mp: len(mp.prefix), reverse=True)

    def find_mount(self, virt_path: str) -> MountPoint:
        norm = posixpath.normpath(virt_path)
        if not norm.startswith("/"):
            norm = "/" + norm

        for mp in self._mount_points:
            if mp.matches(norm):
                return mp

        return MountPoint("/", dev=(259 << 8) | 0, default_uid=0, default_gid=0)

def create_default_mount_table(app_uid: int = 10000) -> 'MountTable':
    return MountTable([
        MountPoint("/system/bin", dev=(259 << 8) | 2, default_uid=0, default_gid=2000, file_mode=0o100755, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_SYSTEM),
        MountPoint("/system/xbin", dev=(259 << 8) | 2, default_uid=0, default_gid=2000, file_mode=0o100755, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_SYSTEM),
        MountPoint("/vendor/bin", dev=(259 << 8) | 2, default_uid=0, default_gid=2000, file_mode=0o100755, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_VENDOR),
        MountPoint("/system", dev=(259 << 8) | 2, default_uid=0, default_gid=0, file_mode=0o100644, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_SYSTEM),
        MountPoint("/vendor", dev=(259 << 8) | 2, default_uid=0, default_gid=0, file_mode=0o100644, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_VENDOR),
        MountPoint("/data/app", dev=(259 << 8) | 3, default_uid=1000, default_gid=1000, file_mode=0o100644, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_APK),
        MountPoint("/data/data", dev=(259 << 8) | 3, default_uid=app_uid, default_gid=app_uid, file_mode=0o100600, dir_mode=0o040700, selinux_context=SELinuxPolicy.CONTEXT_APP_DATA),
        MountPoint("/data/user", dev=(259 << 8) | 3, default_uid=app_uid, default_gid=app_uid, file_mode=0o100600, dir_mode=0o040700, selinux_context=SELinuxPolicy.CONTEXT_APP_DATA),
        MountPoint("/data", dev=(259 << 8) | 3, default_uid=app_uid, default_gid=app_uid, file_mode=0o100755, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_APP_DATA),
        MountPoint("/sdcard", dev=(259 << 8) | 3, default_uid=app_uid, default_gid=app_uid, file_mode=0o100755, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_APP_DATA),
        MountPoint("/dev/__properties__", dev=0x0005, default_uid=0, default_gid=0, file_mode=0o100444, dir_mode=0o040555, selinux_context=SELinuxPolicy.CONTEXT_PROPERTIES),
        MountPoint("/dev", dev=0x0005, default_uid=0, default_gid=0, file_mode=0o100666, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_DEV_NULL),
        MountPoint("/proc", dev=0x000C, default_uid=0, default_gid=0, file_mode=0o100444, dir_mode=0o040555, selinux_context=SELinuxPolicy.CONTEXT_PROC),
        MountPoint("/sys", dev=0x000B, default_uid=0, default_gid=0, file_mode=0o100444, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_SYSFS),
        MountPoint("/", dev=(259 << 8) | 0, default_uid=0, default_gid=0, file_mode=0o100755, dir_mode=0o040755, selinux_context=SELinuxPolicy.CONTEXT_DEFAULT),
    ])