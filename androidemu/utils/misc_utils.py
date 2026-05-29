import os.path
import os

from ..types.alias import _os

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from ..const.linux import *


def vfs_path_to_system_path(vfs_root, path):
    if os.name == 'nt': # ???
        path = path.replace(':', '_')
    fullpath = "%s/%s"%(vfs_root, path)
    return fullpath

def system_path_to_vfs_path(vfs_root, path):
    return "/"+os.path.relpath(path, vfs_root)

def my_open(filepath, flag):
    if(_os == "Windows"):
        flag = flag | os.O_BINARY

    return os.open(filepath, flag)