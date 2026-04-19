import logging
import os
import importlib
import inspect
import pkgutil
import os.path

from pathlib import Path

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from .config import Config

from .data import mem_map as config
from .const import emu_const

from .kernel.syscalls.syscall_handlers import SyscallHandlers
from .kernel.syscalls.syscall_base.syscall_hooks import SyscallHooks
from .kernel.syscalls.syscall_file.file_system import VirtualFileSystem
from .kernel.syscalls.syscall_memory.memory_syscall_handler import MemorySyscallHandler

from .kernel.state.time_manager import TimeManager

from .kernel.pcb import Pcb
from .hooker import Hooker
from .scheduler import Scheduler

from .native_hook_utils import FuncHooker
from .native.symbol_hooks import SymbolHooks

from .internal.linker import AndroidLinker

from .java.java_classloader import JavaClassLoader
from .java.java_vm import JavaVM
from .java.java_class_def import JavaClassDef

from .internal.bionic.tls_factory import create_tls_backend
from .internal.bionic.tls_bionic import BionicTLS

from .utils.memory.memory_map import MemoryMap
from .utils import misc_utils
from .utils.generators import build_prop
from .utils.cpu import CPU_Utils
from .utils.tls import BionicTLSUtils

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .internal.module import Module

class Emulator:

    def __add_classes(self):
        """
        Load all java classes from java/classes directory into the emulator.
        This method is called during the initialization of the emulator.
        It loads all classes from the java/classes directory into the java class loader.
        """
        cur_file_dir = os.path.dirname(__file__)
        
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
        """
        Initialize system properties from build.prop or /dev/__properties__

        :raises FileNotFoundError: if neither build.prop nor /dev/__properties__ is found
        """
        prop = Path(self.__vfs_root) / "system/build.prop"
        prop_bin = Path(self.__vfs_root) / "dev/__properties__"

        has_prop = prop.exists()
        has_bin = prop_bin.exists()

        if not has_prop and not has_bin:
            raise FileNotFoundError("Android property store not found")

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

    def __init_fields(self):
        """
        Initialize Unicorn Emulator
        Set pointer size for current Arch
        Set callbacks for current Arch
        """
        logging.info("process pid:%d"%self.pcb.pid)

        self.__sp_reg = 0

        if self.__arch == emu_const.ARCH_ARM32:
            self.__ptr_sz = 4
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

            self.__sp_reg = UC_ARM_REG_SP
            self.call_native_return_2reg = self.__call_native_return_2reg32


        elif self.__arch == emu_const.ARCH_ARM64:
            self.__ptr_sz = 8
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    
            self.__sp_reg = UC_ARM64_REG_SP
            self.call_native_return_2reg = self.__call_native_return_2reg64

        else:
            raise RuntimeError("emulator arch=%d not support!!!"%self.__arch)
        
    def __setup_env(self):
        """
        Setup environment for Android
        """
        if self.__arch == emu_const.ARCH_ARM32:
            path = "%s/system/lib/vectors"%self.__vfs_root
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = self.__pcb.virtual_files.create_virtual_file(name="[vectors]", name_in_system=path, fd=fd)
            self.memory.map(config.VECTORS_BASE, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)

            path = "%s/system/bin/app_process32"%self.__vfs_root
            sz = os.path.getsize(path)
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = self.__pcb.virtual_files.create_virtual_file(name="/system/bin/app_process32", name_in_system=path, fd=fd)
            self.memory.map(config.APP_PROCESS_BASE, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)
        else:
            path = "%s/system/bin/app_process64"%self.__vfs_root
            sz = os.path.getsize(path)
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = self.__pcb.virtual_files.create_virtual_file(name="/system/bin/app_process64", name_in_system=path, fd=fd)
            self.memory.map(config.APP_PROCESS_BASE, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)

    def __init_syslibs(self):
        """
        Initialize system libraries

        Load libc.so from "system/lib" or "system/lib64" depending on the current arch
        """
        prefix = "system/" + ("lib64/" if self.__arch == emu_const.ARCH_ARM64 else "lib/")
        syslibs = ["libc.so"]

        for lib in syslibs:
            self.load_library(prefix + lib)

    def __init_utils(self):
        """
        Initialize utilities for the emulator
        """
        self.time_manager = TimeManager(start_timestamp=self.config.pkg.start_timestamp)
        self.tls_utils = BionicTLSUtils(self)

    def __init__(self, 
                 vfs_root="vfs",
                 config_path="androidemu/emu_cfg/default.json",
                 vfp_inst_set=True,
                 arch=emu_const.ARCH_ARM32,
                 init_sys_libs=True,
                 **kwargs
                 ):

        # logging.warning("LIEF Leaks Warning Disabled!")

        """
        Initialize emulator

        Parameters
        ----------
        vfs_root : str
            Root path for virtual file system
        config_path : str
            Path to configuration package
        vfp_inst_set : bool
            Enable VFP instructions
        arch : int
            Current architecture (32 or 64 bit). 1 or 2
        init_sys_libs : bool
            Initialize system libraries
        **kwargs
            Additional keyword arguments (for deprecated arguments)
        """

        self.config = Config(config_path)
        self.__arch = arch
        self.__vfs_root = vfs_root
        
        self.__pcb = Pcb(self, self.config) # For VFS we make post-init call after init Ya i know how it's bad.
        self.__pcb.post_init() #self.virtual_files

        # Unicorn
        self.__init_fields()

        # asm instructions
        self.mu.mem_map(config.ASM_CODE, config.PAGE_SIZE, UC_PROT_WRITE | UC_PROT_EXEC)
        
        self.__cpu_utils = CPU_Utils(self)

        if vfp_inst_set:
            if self.__arch == emu_const.ARCH_ARM32:
                self.__cpu_utils._enable_vfp32()
            elif self.__arch == emu_const.ARCH_ARM64:
                self.__cpu_utils._enable_vfp64()

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

        # Linker & TLS
        self.tls_state: 'BionicTLS' = create_tls_backend(self)
        self.linker = AndroidLinker(self, self.__vfs_root)

        # Hooks
        self.func_hooker = FuncHooker(self)
        self.sym_hooks = SymbolHooks(self)

        self.__init_utils()

        # Syscalls
        self.mem_handler = MemorySyscallHandler(self, self.memory, self.__syscall_handler)
        self.syscall_hooks = SyscallHooks(self, self.__syscall_handler)
        self.vfs = VirtualFileSystem(self, vfs_root, self.__syscall_handler)

        # Java Loader
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self._hooker)
        
        self.__add_classes()

        # Hack jmethod_id
        self.memory.map(config.JMETHOD_ID_BASE, 0x2000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        self.__setup_env()

        if init_sys_libs:
            self.__init_properties()
            self.__init_syslibs()
    
    def sys_reg_read(self, reg):
        """
        Read Non-Implement System Registers
        """
        return self.__cpu_utils._read_sys_reg(reg)

    def sys_reg_write(self, reg, val):
        """
        Write Non-Implement System Registers
        """
        return self.__cpu_utils._write_sys_reg(reg, val)

    def load_library(self, filename, do_init: bool = True, main_lib: bool = False, demangle: bool = False) -> 'Module':
        """
        Load a dynamic library from disk.

        :param filename: The name of the library (e.g. libfoo.so)
        :param do_init: Whether to initialize the library with init_array
        :param main_lib: Whether this is the main executable
        :param demangle: Whether to demangle symbols (functions, exported symbols, etc.)
        :return: The loaded module

        WARNING: Demangle option can increase memory consumption for store more symbols.
        """
        libmod = self.linker.load_module(filename, do_init, main_lib, demangle)
        return libmod

    # alias-like
    def get_library(self, filename) -> 'Module':
        """
        Get a loaded library.

        :param filename: The name of the library
        :return: The loaded module, or None if the library is not loaded.
        """
        if self.linker.find_module_by_name(filename) is None:
            logging.error("Library '%s' is not loaded!", filename)
            return None
        return self.load_library(filename)

    def call_symbol(self, module: 'Module', symbol_name: str, *argv) -> int:
        """
        Call a symbol in a module.

        :param module: The module containing the symbol
        :param symbol_name: The name of the symbol
        :param *argv: The arguments to pass to the symbol
        :return: The return value of the symbol
        """
        symbol_addr = module.find_symbol(symbol_name)
        if symbol_addr is None:
            logging.error('Unable to find symbol \'%s\' in module \'%s\'.' % (symbol_name, module.filename))
            return

        return self.call_native(symbol_addr, *argv)

    def call_function(self, module: 'Module', function_name: str, *argv) -> int:
        """
        Use it for non-export functions, like in libc
        """
        symbol_addr = module.find_function(function_name)
        if symbol_addr is None:
            logging.error('Unable to find function \'%s\' in module \'%s\'.' % (function_name, module.filename))
            return

        return self.call_native(symbol_addr, *argv)
    
    def call_native(self, addr, *argv) -> int:
        """
        Call a native function with the given address and arguments.

        :param addr: The address of the native function
        :param *argv: The arguments to pass to the native function
        :return: The return value of the native function
        """
        assert addr is not None, "call addr is None!"
        return self.__sch.call_native(addr, *argv)

    # The 8-byte return value is split across two registers.
    def __call_native_return_2reg32(self, addr, *argv) -> int:
        """
        The 8-byte return value is split across two registers.
        The high 4 bytes are stored in R1 and the low 4 bytes are stored in the return value.
        This function combines the two parts of the return value into a single 8-byte value.
        :param addr: The address of the native function
        :param *argv: The arguments to pass to the native function
        :return: The return value of the native function
        """
        res = self.call_native(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM_REG_R1)

        return (res_high << 32) | res

    # The 16-byte return value is split across two registers.
    def __call_native_return_2reg64(self, addr, *argv) -> int:
        """
        The 16-byte return value is split across two registers.
        The high 8 bytes are stored in X1 and the low 8 bytes are stored in the return value.
        This function combines the two parts of the return value into a single 16-byte value.
        :param addr: The address of the native function
        :param *argv: The arguments to pass to the native function
        :return: The return value of the native function
        """
        res = self.call_native(addr, *argv)

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