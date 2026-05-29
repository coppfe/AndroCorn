import re

class FileModeMap:

    FS_MAP = [
        (re.compile(r'^/proc($|/.*)'),         (0, 12)),  # 0:1
        (re.compile(r'^/sys($|/.*)'),          (0, 11)),  # 0:11
        (re.compile(r'^/dev/pts($|/.*)'),      (0, 15)),  # 0:15
        (re.compile(r'^/dev($|/.*)'),          (0, 5)),   # 0:5 (devtmpfs)
        (re.compile(r'^/vendor($|/.*)'),       (259, 1)), # 259:1
        (re.compile(r'^/system($|/.*)'),       (259, 2)), # 259:2
        (re.compile(r'^/data($|/.*)'),         (259, 3)), # 259:3
        (re.compile(r'^/'),                    (259, 0)), # 259:0
    ]

    CHAR_DEVS = {
        "/dev/null":         (1, 3),
        "/dev/zero":         (1, 5),
        "/dev/full":         (1, 7),
        "/dev/random":       (1, 8),
        "/dev/urandom":      (1, 9),
        "/dev/ptmx":         (5, 2),
        "/dev/tty":          (5, 0),
        "/dev/ashmem":       (10, 62),
        "/dev/binder":       (10, 61),
    }

    @classmethod
    def get_st_dev(cls, path: str) -> int:
        for pattern, (major, minor) in cls.FS_MAP:
            if pattern.match(path):
                return (major << 8) | minor
        return (253 << 8) | 0

    @classmethod
    def get_st_rdev(cls, path: str) -> int:
        if path in cls.CHAR_DEVS:
            major, minor = cls.CHAR_DEVS[path]
            return (major << 8) | minor
        return 0
