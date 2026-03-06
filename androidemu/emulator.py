import logging
import os
import importlib
import inspect
import pkgutil
import sys
import os.path

from pathlib import Path

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from .config import Config

from .data import mem_map as config
from .const import emu_const

from .core.handlers.syscall_base.syscall_handlers import SyscallHandlers
from .core.handlers.syscall_base.syscall_hooks import SyscallHooks
from .core.handlers.syscall_file.file_system import VirtualFileSystem
from .core.handlers.syscall_memory.memory_syscall_handler import MemorySyscallHandler

from .core.state.time_manager import TimeManager

from .objects.virtual_file import VirtualFile

from .pcb import Pcb
from .hooker import Hooker
from .scheduler import Scheduler

from .native_hook_utils import FuncHooker
from .native.symbol_hooks import SymbolHooks

from .internal.linker import AndroidLinker

from .java.helpers.native_method import native_write_args
from .java.java_classloader import JavaClassLoader
from .java.java_vm import JavaVM
from .java.java_class_def import JavaClassDef

from .internal.bionic.tls_factory import create_tls_backend
from .internal.bionic.tls_bionic import BionicTLS

from .utils.memory.memory_map import MemoryMap
from .utils import misc_utils
from .utils.generators import build_prop
from .utils.cpu import CPU_Utils

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .internal.module import Module


class Emulator:

    def __add_classes(self):
        cur_file_dir = os.path.dirname(__file__)
        
        #python 约定 package_name总是相对于入口脚本目录
        package_name = "androidemu"

        full_dirname = "%s/java/classes"%(cur_file_dir, )

        preload_classes = set()
        for importer, mod_name, c in pkgutil.iter_modules([full_dirname]):
            import_name = ".java.classes.%s"%mod_name
            m = importlib.import_module(import_name, package_name)
            clsList = inspect.getmembers(m, inspect.isclass)
            for _, clz in clsList:
                if (type(clz) == JavaClassDef):
                    preload_classes.add(clz)

        for clz in preload_classes:
            self.java_classloader.add_class(clz)

        #also add classloader as java class
        self.java_classloader.add_class(JavaClassLoader)

    def __init_properties(self):
        # hell nahw
        prop = Path(self.__vfs_root) / "system/build.prop"
        prop_bin = Path(self.__vfs_root) / "dev/__properties__"

        has_prop = prop.exists()
        has_bin = prop_bin.exists()

        if not has_prop and not has_bin:
            raise RuntimeError("Android property store not found")

        self.system_properties = {}

        if has_bin:
            logging.info("[+] Detected Android property service (/dev/__properties__)")

        if has_prop:
            msg = "[+] Initializing from build.prop" if has_bin else "[+] Using build.prop (legacy mode)"
            logging.info(msg)
            self.system_properties = build_prop.parse_prop_file(prop)

        if has_prop and not has_bin:
            logging.info("[+] build.prop found but property area missing -> generating (__properties__)")
            gen = build_prop.PropAreaGenerator()
            for key, value in self.system_properties.items():
                gen.add_property(key, value)
            gen.save(prop_bin)
            has_bin = prop_bin.exists()

        elif not has_prop and has_bin:
            logging.warning("[!] build.prop missing, properties will be empty")

    def __init_fields(self, vfp_inst_set):
        logging.info("process pid:%d"%self.pid)

        self.__sp_reg = 0

        if self.__arch == emu_const.ARCH_ARM32:
            self.__ptr_sz = 4
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            if vfp_inst_set:
                utils = CPU_Utils(self)
                utils._enable_vfp32()

            self.__sp_reg = UC_ARM_REG_SP
            self.call_native = self.__call_native32
            self.call_native_return_2reg = self.__call_native_return_2reg32


        elif self.__arch == emu_const.ARCH_ARM64:
            self.__ptr_sz = 8
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            if vfp_inst_set:
                utils = CPU_Utils(self)
                utils._enable_vfp64()
    
            self.__sp_reg = UC_ARM64_REG_SP

            self.call_native = self.__call_native64
            self.call_native_return_2reg = self.__call_native_return_2reg64

        else:
            raise RuntimeError("emulator arch=%d not support!!!"%self.__arch)

    def __init_syslibs(self):
        prefix = "system/" + ("lib64/" if self.__arch == emu_const.ARCH_ARM64 else "lib/")
        syslibs = ["libc.so"]

        for lib in syslibs:
            self.linker.load_module(prefix + lib)

    def __init__(self, vfs_root="vfs", config_path="androidemu/emu_cfg/default.json", vfp_inst_set=True, arch=emu_const.ARCH_ARM32, muti_task=False):
        self.config = Config(config_path)
        
        self.__arch = arch
        self.__support_muti_task = muti_task
        self.__vfs_root = vfs_root
        self.__pcb = Pcb(self.config)

        self.pid = self.__pcb.get_pid()
        self.tid = self.__pcb.generate_new_tid()
        self.uid = self.__pcb.get_uid()

        self.__init_fields(vfp_inst_set)
        #self.mu.mem_map(0x0, 0x00001000, UC_PROT_READ | UC_PROT_WRITE)

        # NOTE: there was a bug before — the linker initialization did not complete the init_tls step.
        # As a result, libc initialization accessed a null pointer and could not finish normally.
        # Here we map address 0 directly to force the execution to continue,
        # because R1 happens to be 0; otherwise a memory unmapped exception would occur.
        # This issue has been fixed in the latest version, so this mapping is no longer needed.

        self.__init_properties()

        self.memory = MemoryMap(self.mu, config.MAP_ALLOC_BASE, config.MAP_ALLOC_BASE+config.MAP_ALLOC_SIZE)

        # Stack init
        self.memory.map(config.STACK_ADDR, config.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.reg_write(self.__sp_reg, (config.STACK_ADDR + config.STACK_SIZE) - 0x4000)

        # Scheduler
        self.__sch = Scheduler(self)

        # CPU
        self.__syscall_handler = SyscallHandlers(self.mu, self.__sch, self.arch)

        # Hooker
        self.memory.map(config.BRIDGE_MEMORY_BASE, config.BRIDGE_MEMORY_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self._hooker = Hooker(self, config.BRIDGE_MEMORY_BASE, config.BRIDGE_MEMORY_SIZE)

        # Syscalls
        self.mem_handler = MemorySyscallHandler(self, self.memory, self.__syscall_handler)
        self.syscall_hooks = SyscallHooks(self, self.config, self.__syscall_handler)
        self.vfs = VirtualFileSystem(self, vfs_root, self.config, self.__syscall_handler, self.memory)

        # Utils
        self.time_manager = TimeManager()

        # Linker & TLS
        self.tls_state: 'BionicTLS' = create_tls_backend(self)
        self.linker = AndroidLinker(self, self.__vfs_root)

        # Hooks
        self.func_hooker = FuncHooker(self)
        self.sym_hooks = SymbolHooks(self)

        self.__init_syslibs()

        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self._hooker)
        
        self.__add_classes()

        # Hack jmethod_id
        self.memory.map(config.JMETHOD_ID_BASE, 0x2000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        self.__setup_env()

    def __setup_env(self):
        if self.__arch == emu_const.ARCH_ARM32:
            path = "%s/system/lib/vectors"%self.__vfs_root
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = VirtualFile("[vectors]", fd, path)
            self.memory.map(0xffff0000, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)

            path = "%s/system/bin/app_process32"%self.__vfs_root
            sz = os.path.getsize(path)
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = VirtualFile("/system/bin/app_process32", fd, path)
            self.memory.map(0xab006000, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)
        else:
            path = "%s/system/bin/app_process64"%self.__vfs_root
            sz = os.path.getsize(path)
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = VirtualFile("/system/bin/app_process64", fd, path)
            self.memory.map(0xab006000, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)

    def load_library(self, filename, do_init: bool = False, main_lib: bool = False) -> 'Module':
        libmod = self.linker.load_module(filename, do_init, main_lib)
        return libmod
    
    # alias-like
    def get_library(self, filename) -> 'Module':
        return self.load_library(filename)

    def call_symbol(self, module: 'Module', symbol_name: str, *argv) -> int:
        symbol_addr = module.find_symbol(symbol_name)
        if symbol_addr is None:
            logging.error('Unable to find symbol \'%s\' in module \'%s\'.' % (symbol_name, module.filename))
            return

        return self.call_native(symbol_addr, *argv)
    
    def call_function(self, module: 'Module', function_name: str, *argv) -> int:
        """
        Use it for non-export functions
        """
        symbol_addr = module.find_function(function_name)
        if symbol_addr is None:
            logging.error('Unable to find function \'%s\' in module \'%s\'.' % (function_name, module.filename))
            return

        return self.call_native(symbol_addr, *argv)

    def __call_native32(self, addr, *argv) -> int:
        assert addr is not None, "call addr is None!"
        return self.__sch.call_native(addr, *argv)

    def __call_native64(self, addr, *argv) -> int:
        assert addr is not None, "call addr is None!"
        return self.__sch.call_native(addr, *argv)

    # The 8-byte return value is split across two registers.
    def __call_native_return_2reg32(self, addr, *argv) -> int:
        res = self.__call_native32(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM_REG_R1)

        return (res_high << 32) | res

    # The 16-byte return value is split across two registers.
    def __call_native_return_2reg64(self, addr, *argv) -> int:
        res = self.__call_native64(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM64_REG_X1)

        return (res_high << 64) | res

    @property
    def vfs_root(self) -> str:
        return self.__vfs_root

    @property
    def arch(self) -> int:
        return self.__arch

    @property
    def ptr_size(self) -> int:
        return self.__ptr_sz

    @property
    def pcb(self) -> 'Pcb':
        return self.__pcb
    
    @property
    def scheduler(self) -> 'Scheduler':
        return self.__sch

    @property
    def muti_task(self) -> bool:
        return self.__support_muti_task