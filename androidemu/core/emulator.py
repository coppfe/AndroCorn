import logging
import os
import importlib
import inspect
import pkgutil
import os.path

from pathlib import Path

from unicorn import *

from ..data.config import Config

from ..data import mem_map as config
from ..const import emu_const

from ..arguments.process import ProcessArgumentsBlock
from ..arguments.system  import SystemArgumentsBlock

from .process.pcb import ProcessControlBlock
from ..utils.hooker import Hooker
from ..cpu.scheduler import Scheduler
from ..native.init_hooks import HooksInitializer

from ..utils.hookers.address import AddressHooker
from ..utils.memory.map import MemoryMap
from ..utils import misc_utils
from ..utils.generators import device_properties
from ..utils.cpu import CPU_Utils
from ..utils.tls import BionicTLSUtils

from .state.time_manager import TimeManager
from .state._global      import GlobalContextMachine

from ..cpu.handlers.syscall import SyscallsHandler
from ..kernel.init import SysInit

from ..internal.bionic.tls_factory import create_tls_backend
from ..internal.bionic.tls_bionic import BionicTLS
from ..internal.linker import AndroidLinker

from ..java.classloader import JavaClassLoader
from ..java.jvm.main import JavaVM
from ..java.class_def import JavaClassDef

from ..native.helpers.args import write_args

from ..objects.registers import RegistersMapping

from ..types.alias import set_types

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ..internal.module import Module
    from androidemu.data.states.process import ProcessState


class Emulator:
    """
    Main class of Emulator. Store everything you need.

    :param vfs_root: The root of the virtual file system
    :param config_path: The path to the configuration package
    :param vfp_inst_set: Enable VFP instructions
    :param arch: Current architecture (32 or 64 bit). 1 (ARM32) or 2 (ARM64) (default: 1)
    :param init_sys_libs: Initialize system libraries
    """

    def _add_classes(self):
        """
        Load all java classes from java/classes directory into the emulator.
        This method is called during the initialization of the emulator.
        It loads all classes from the java/classes directory into the java class loader.
        """
        current_file = Path(__file__).resolve()

        package_name = "androidemu"

        package_root = current_file.parent
        while package_root.name != "androidemu" and package_root != package_root.parent:
            package_root = package_root.parent

        if package_root == package_root.parent:
            package_root = current_file.parent
            
        full_dirname = str(package_root / "java" / "classes")

        preload_classes = set()
        for importer, mod_name, c in pkgutil.iter_modules([full_dirname]):
            import_name = f".java.classes.{mod_name}"
            m = importlib.import_module(import_name, package_name)
            clsList = inspect.getmembers(m, inspect.isclass)
            for _, clz in clsList:
                if type(clz) == JavaClassDef:
                    preload_classes.add(clz)

        for clz in preload_classes:
            self.java_classloader.add_class(clz)

        # also add classloader as java class
        self.java_classloader.add_class(JavaClassLoader)

    def _init_properties(self):
        # hell nahw
        """
        Initialize system properties from build.prop or /dev/__properties__

        :raises FileNotFoundError: if neither build.prop nor /dev/__properties__ is found
        """
        prop = Path(self.vfs_root) / "system/build.prop"
        prop_bin = Path(self.vfs_root) / "dev/__properties__"

        has_prop = prop.exists()
        has_bin = prop_bin.exists()

        if not has_prop and not has_bin:
            raise FileNotFoundError("Android property store not found")

        self.system_properties = {}

        if has_bin:
            logging.info("[+] Detected Android property service (/dev/__properties__)")

        if has_prop:
            msg = (
                "[+] Initializing from build.prop"
                if has_bin
                else "[+] Using build.prop (legacy mode)"
            )
            logging.info(msg)
            self.system_properties = device_properties.parse_prop_file(prop)

        if has_prop and not has_bin:
            logging.info(
                "[+] build.prop found but property area missing -> generating (__properties__)"
            )
            gen = device_properties.PropAreaGenerator()
            for key, value in self.system_properties.items():
                gen.add_property(key, value)
            gen.save(prop_bin)
            has_bin = prop_bin.exists()

        elif not has_prop and has_bin:
            logging.warning("[!] build.prop missing, properties will be empty")

    def _init_fields(self):
        """
        Initialize Unicorn Emulator
        Set pointer size for current Arch
        Set callbacks for current Arch
        """
        if self.arch == emu_const.ARCH_ARM32:
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        elif self.arch == emu_const.ARCH_ARM64:
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        else:
            raise RuntimeError(
                "Wrong arch identifier. Except '1' for ARM32 or '2' for ARM64"
            )  # Never here.

    def _setup_env(self):
        """
        Setup environment for Android
        """
        num = "32" if self.mu._arch == emu_const.ARCH_ARM32 else "64"

        vectors = self.vfs_root + "/system/lib/vectors"
        app_process = "/system/bin/app_process" + num

        if self.arch == emu_const.ARCH_ARM32:
            fd = misc_utils.my_open(vectors, os.O_RDONLY)
            vf = self.pcb.virtual_files.create_virtual_file(
                name="[vectors]", name_in_system=vectors, fd=fd
            )
            self.memory.map(
                config.VECTORS_BASE, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0
            )
            os.close(fd)

        path = self.vfs_root + app_process
        sz = os.path.getsize(path)
        fd = misc_utils.my_open(path, os.O_RDONLY)
        vf = self.pcb.virtual_files.create_virtual_file(
            name=app_process, name_in_system=path, fd=fd
        )
        self.memory.map(config.APP_PROCESS_BASE, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
        os.close(fd)

    def _init_syslibs(self):
        """
        Initialize system libraries

        Load libc.so from "system/lib" or "system/lib64" depending on the current arch
        """
        syslibs = ["libc.so"]

        for lib in syslibs:
            self.load_library(lib)

    def _init_utils(self):
        """
        Initialize utilities for the emulator
        """
        self.time_manager = TimeManager(start_timestamp=self.config.pkg.start_timestamp)
        self.tls_utils = BionicTLSUtils(self.mu, self.registers)
        self._cpu_utils = CPU_Utils(self.mu)

    def __init__(
        self,
        vfs_root: str = "vfs",
        config_path: str = "androidemu/emu_cfg/default.json",
        vfp_inst_set: bool = True,
        arch: int = emu_const.ARCH_ARM32,
        init_sys_libs: bool = True,
        **kwargs: Any,
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
        set_types(arch)
        
        self.config = Config(config_path)
        self.ctx = GlobalContextMachine()
        self.arch = arch
        self.vfs_root = vfs_root
        self.registers = RegistersMapping(self.arch)  # Registers

        self._init_properties()

        self._init_fields()  # Unicorn fields
        self._init_utils()   # Utils fields

        self.memory = MemoryMap(
            self.mu,
            config.MAP_ALLOC_BASE,
            config.MAP_ALLOC_BASE + config.MAP_ALLOC_SIZE
        )

        # Memory init
        self.memory.map(
            config.ASM_CODE, config.PAGE_SIZE, UC_PROT_WRITE | UC_PROT_EXEC
        )  # asm instructions
        self.memory.map(
            config.STACK_ADDR, config.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE
        )  # Stack Addr
        self.memory.map(
            config.STOP_MEMORY_BASE,
            config.STOP_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_EXEC,
        )  # JMP to python
        self.memory.map(
            config.BRIDGE_MEMORY_BASE,
            config.BRIDGE_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )  # Hook bridge
        self.memory.map(
            config.JMETHOD_ID_BASE, 0x2000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC
        )  # Hack jmethod_id

        if vfp_inst_set:
            if self.arch == emu_const.ARCH_ARM32:
                self._cpu_utils._enable_vfp32()
            elif self.arch == emu_const.ARCH_ARM64:
                self._cpu_utils._enable_vfp64()

        self.mu.reg_write(
            self.registers.sp, (config.STACK_ADDR + config.STACK_SIZE) - 0x4000 # reserve
        )        
        
        self.pcb = ProcessControlBlock(self.mu, self.config, self.ctx)  # Process Control Block
        self._setup_env()

        self.tls_state: "BionicTLS" = create_tls_backend(
            self.memory, self.mu, self.arch
        )
        self.linker = AndroidLinker(self, self.vfs_root)

        self.scheduler = Scheduler(
            self.mu,
            self.registers,
            self.memory,
            self.pcb,
            self.time_manager,
            self.ctx
        )  # CPU Scheduler

        _sysarg_block = SystemArgumentsBlock(
            self.arch,
            self.vfs_root,
            self.config,
            self.time_manager,
            self.registers,
            self.linker,
            self.system_properties
        )
        _procarg_block = ProcessArgumentsBlock(
            self,
            self.mu,
            self.memory,
            self.pcb,
            self.scheduler,
            self.tls_utils,
            self.ctx
        )

        # Syscalls
        self._syscall_handler = SyscallsHandler(self.mu, self.registers)
        SysInit(_procarg_block, _sysarg_block, self._syscall_handler.set_handler)

        self._hooker = Hooker(
            self,
            self.mu,
            config.BRIDGE_MEMORY_BASE,
            config.BRIDGE_MEMORY_SIZE,
        )  # Hooker

        # Hooks
        self.address_hooker = AddressHooker(self)
        self.hooks = HooksInitializer(self)

        # Java Loader
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self._hooker)

        self._add_classes()

        if init_sys_libs:
            self._init_syslibs()

        ctx: 'ProcessState' = self.ctx
        logging.info("process pid:%d", ctx.pid)

    def sys_reg_read(self, reg: int) -> int:
        """
        Read Non-Implement System Registers

        :type reg: int

        :param reg: The register to read

        :return: The value of the register
        """
        return self._cpu_utils._read_sys_reg(reg)

    def sys_reg_write(self, reg: int, val: int) -> None:
        """
        Write Non-Implement System Registers

        :type reg: int
        :type val: int

        :param reg: The register to write
        :param val: The value to write

        :return: None
        """
        return self._cpu_utils._write_sys_reg(reg, val)

    def load_library(
        self, filename: str, do_init: bool = True, main_lib: bool = False
    ) -> "Module":
        """
        Load a dynamic library from disk.

        :type filename: str
        :type do_init: bool
        :type main_lib: bool

        :param filename: The name of the library (e.g. libfoo.so)
        :param do_init: Whether to initialize the library with init_array
        :param main_lib: Whether this is the main executable

        :return: The loaded module
        """
        libmod = self.linker.load_module(filename, do_init, main_lib)
        return libmod

    # alias-like
    def get_library(self, filename: str) -> Optional["Module"]:
        """
        Get a loaded library.

        :type filename: str

        :param filename: The name of the library
        :return: The loaded module, or None if the library is not loaded.
        """
        if self.linker.find_module_by_name(filename) is None:
            logging.error("Library '%s' is not loaded!", filename)
            return None
        return self.load_library(filename)

    def call_symbol(
        self, module: "Module", symbol_name: str, *argv: Any
    ) -> Optional[int]:
        """
        Call a symbol in a module.

        :type module: Module
        :type symbol_name: str

        :param module: The module containing the symbol
        :param symbol_name: The name of the symbol
        :param *argv: The arguments to pass to the symbol
        :return: The return value of the symbol
        """
        symbol_addr = module.find_symbol(symbol_name)
        if symbol_addr is None:
            logging.error(
                "Unable to find symbol '%s' in module '%s'."
                , symbol_name, module.filename
            )
            return

        return self.call_native(symbol_addr, *argv)

    def call_function(
        self, module: "Module", function_name: str, *argv: Any
    ) -> Optional[int]:
        """
        Use it for non-export functions, like in libc

        :type module:        Module
        :type function_name: str

        :param module: The module containing the function
        :param function_name: The name of the function
        :param *argv: The arguments to pass to the function
        :return: The return value of the function
        """
        symbol_addr = module.find_function(function_name)
        if symbol_addr is None:
            logging.error(
                "Unable to find function '%s' in module '%s'."
                , function_name, module.filename
            )
            return

        return self.call_native(symbol_addr, *argv)

    def call_native(self, addr: int, *argv: Any) -> Optional[int]:
        """
        Call a native function with the given address and arguments.

        :type addr: int

        :param addr: The address of the native function
        :param *argv: The arguments to pass to the native function
        :return: The return value of the native function
        """
        assert addr is not None, "call addr is None!"

        if not self.scheduler._is_running:
            write_args(
                self.mu, self.java_vm, self.registers, *argv
            )
            self.scheduler.exec(addr)
            return self.mu.reg_read(self.registers.ret)

        else:
            # for nested calls we just dump context and setting pc to addr
            saved_context = self.mu.context_save()
            interrupted_pc = self.mu.reg_read(self.registers.pc)  # last known pc

            try:
                smb = config.STOP_MEMORY_BASE
                write_args(
                    self.mu, self.java_vm, self.registers, *argv
                )
                self.mu.reg_write(self.registers.pc, addr)
                self.mu.reg_write(self.registers.lr, smb)

                logging.debug(f"Nested call to 0x{addr:x} from 0x{interrupted_pc:x}")
                self.mu.emu_start(addr, smb, 0, 0)

                if self.mu.reg_read(self.registers.pc) != smb:
                    logging.warning(
                        f"Nested call to 0x{addr:x} was INTERRUPTED before completion!"
                    )

                return_value = self.mu.reg_read(self.registers.ret)
                return return_value

            except UcError as e:
                logging.error(f"Crash in nested call to 0x{addr:x}: {e}")
                raise

            finally:
                self.mu.context_restore(saved_context)

    def call_native_return_2reg(self, addr: int, *argv: Any) -> Optional[int]:
        """
        The 8 (or 16) byte return value is split across two registers.
        The high (4 or 8) bytes are stored in R1 (X1) and the low (4 or 8) bytes are stored in the return value.
        This function combines the two parts of the return value into a single 8 (or 16) byte value.
        :param addr: The address of the native function
        :param *argv: The arguments to pass to the native function
        :return: The return value of the native function
        """
        res = self.call_native(addr, *argv)
        off = 32 if self.arch == emu_const.ARCH_ARM32 else 64

        res_high = self.mu.reg_read(self.registers.any_1)

        return (res_high << off) | res