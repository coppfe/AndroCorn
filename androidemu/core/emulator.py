import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

from unicorn import *

from ..const import emu_const
from ..cpu.handlers.syscall import SyscallsHandler
from ..cpu.scheduler import Scheduler
from ..data import layout as config
from ..data.config import Config
from ..emu_cfg.default import DEFAULT_PACKAGE
from ..internal.bionic.tls.factory import create_tls_backend
from ..internal.bionic.tls.init import BionicTLSInitialization
from ..internal.linker import AndroidLinker
from ..java.class_def import JavaClassDef
from ..java.classloader import JavaClassLoader
from ..java.jvm.main import JavaVM
from ..kernel.fs.manager import VFSManager
from ..kernel.init import SysInit
from ..native.init_hooks import HooksInitializer
from .registers import RegistersMapping
from ..types.alias import set_types
from ..utils.cpu import CPU_Utils
from ..utils.hooker import Hooker
from ..native.hook.manager import HookManager
from ..utils.memory.map import MemoryMap
from ..utils.parsers.properties import parse_prop_file
from ..utils.tls import BionicTLSUtils
from .pcb import ProcessControlBlock
from .state.time_manager import TimeManager

if TYPE_CHECKING:
    from ..internal.module import Module


class Emulator:
    """
    Main class of Emulator. Store everything you need.

    :param vfs_root: The root of the virtual file system
    :param environment: The configuration package
    :param vfp_inst_set: Enable VFP instructions
    :param arch: Current architecture (32 or 64 bit). 1 (ARM32) or 2 (ARM64) (default: 1)
    :param init_sys_libs: Initialize system libraries
    """
    def __init__(
        self,
        vfs_root: str = "vfs",
        environment: Dict = DEFAULT_PACKAGE,
        vfp_inst_set: bool = True,
        arch: int = emu_const.ARCH_ARM32,
        init_sys_libs: bool = True,
        **kwargs: Any,
    ):
        self.arch = arch
        self.vfs_root = vfs_root

        # 1. State, Configuration & Properties
        self._init_core_state(environment)
        self._init_properties()

        # 2. CPU & Engine
        self._init_engine()

        # 3. Memory Subsystem
        self._init_memory_layout(vfp_inst_set)

        # 4. TLS & Linker
        self._init_linker()

        # 5. VFS Engine
        self.vfs = VFSManager(self)

        # 6. Process Context & Base Environment (PCB, app_process, vectors)
        self._init_process_and_vfs()

        # 7. Execution Subsystem (Scheduler, Syscalls, SysInit)
        self._init_execution_subsystem()

        # 8. Hooks
        self._init_hooks()

        # 9. Java Runtime
        self._init_java_runtime()

        # 10. System Libraries
        if init_sys_libs:
            self._init_syslibs()

        logging.info("[+] Emulator ready. Process PID: %d", self.pcb.pid)

    def _init_core_state(self, environment: Dict) -> None:
            set_types(self.arch)
            self.config = Config(environment)
            self.pcb = ProcessControlBlock(self.config)

    def _init_properties(self) -> None:
        prop_bin = Path(self.vfs_root) / "dev/__properties__"
        if not prop_bin.exists():
            raise FileNotFoundError(
                f"Android property file not found at '{prop_bin}'. "
                "Ensure '/dev/__properties__' exists in your VFS."
            )
        prop_txt = Path(self.vfs_root) / "system/build.prop"
        self.system_properties = (
            parse_prop_file(prop_txt) if prop_txt.exists() else {}
        )

    def _init_engine(self) -> None:
        if self.arch == emu_const.ARCH_ARM32:
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        elif self.arch == emu_const.ARCH_ARM64:
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        else:
            raise ValueError(f"Unsupported arch identifier: {self.arch}")
        
        self.registers = RegistersMapping(self.mu, self.arch)
        self.time_manager = TimeManager(start_timestamp=self.config.pkg.start_timestamp)
        self.tls_utils = BionicTLSUtils(self.mu, self.registers)
        self._cpu_utils = CPU_Utils(self.mu)

    def _init_memory_layout(self, vfp_inst_set: bool) -> None:
        self.memory = MemoryMap(
            self.mu,
            config.EMU_HEAP_BASE,
            config.EMU_HEAP_BASE + config.EMU_HEAP_SIZE,
        )

        self.memory.map(config.ASM_CODE, config.PAGE_SIZE, UC_PROT_WRITE | UC_PROT_EXEC)
        self.memory.map(config.STACK_ADDR, config.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.memory.map(config.STOP_MEMORY_BASE, config.STOP_MEMORY_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.memory.map(config.BRIDGE_MEMORY_BASE, config.BRIDGE_MEMORY_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self.memory.map(config.JMETHOD_ID_BASE, 0x2000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        self.memory.map(config.BRK_BASE, config.BRK_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        if vfp_inst_set:
            if self.arch == emu_const.ARCH_ARM32:
                self._cpu_utils._enable_vfp32()
            elif self.arch == emu_const.ARCH_ARM64:
                self._cpu_utils._enable_vfp64()

        self.registers.v_sp = (config.STACK_ADDR + config.STACK_SIZE) - 0x4000

    def _init_linker(self) -> None:
        self.tls_state: "BionicTLSInitialization" = create_tls_backend(
            self.memory, self.mu, self.registers
        )
        self.linker = AndroidLinker(self, self.vfs_root)

    def _init_process_and_vfs(self) -> None:
        # self.pcb = ProcessControlBlock(self.mu, self.config, self.ctx)
        self._setup_env()

    def _setup_env(self) -> None:
        is_64 = (self.arch == emu_const.ARCH_ARM64)
        
        app_process = "/system/bin/app_process64" if is_64 else "/system/bin/app_process32"
        linker_bin = "/system/bin/linker64" if is_64 else "/system/bin/linker"

        if not is_64:
            vectors = os.path.join(self.vfs_root, "system", "lib", "vectors")
            if os.path.exists(vectors):
                node = self.vfs.get_node("/system/lib/vectors")
                if node:
                    self.memory.map(config.VECTORS_BASE, 0x1000, UC_PROT_EXEC | UC_PROT_READ, node=node, offset=0)

        node_app = self.vfs.get_node(app_process)
        if node_app:
            sz = node_app.get_size()
            self.memory.map(config.APP_PROCESS_BASE, sz, UC_PROT_EXEC | UC_PROT_READ, node=node_app, offset=0)

        node_linker = self.vfs.get_node(linker_bin)
        if node_linker:
            sz = node_linker.get_size()
            self.memory.map(config.LINKER_BASE, sz, UC_PROT_EXEC | UC_PROT_READ, node=node_linker, offset=0)
            logging.debug(f"[+] Loaded {linker_bin} into memory at 0x{config.LINKER_BASE:08X}")

    def _init_execution_subsystem(self) -> None:
        self.scheduler = Scheduler(
            self.mu, self.registers, self.memory,
            self.pcb, self.time_manager, self.vfs
        )
        self._syscall_handler = SyscallsHandler(self)
        SysInit(self, self._syscall_handler.set_handler)

    def _init_hooks(self) -> None:
        self._hooker = Hooker(
            self,
            self.mu,
            config.BRIDGE_MEMORY_BASE,
            config.BRIDGE_MEMORY_SIZE,
        )
        self.hook_manager = HookManager(self)
        HooksInitializer(self)

    def _init_java_runtime(self) -> None:
        self.java_classloader = JavaClassLoader()
        self._init_base_java_classes()
        self.java_vm = JavaVM(self, self.java_classloader, self._hooker)

    def _init_base_java_classes(self) -> None:
        from ..java.classes.java.lang.clazz import Class
        from ..java.classes.java.lang.object import Object
        from ..java.classes.java.lang.string import String
        from ..java.classes.java.lang.system import System
        from ..java.classes.java.lang.types import Boolean, Integer, Long, Float
        from ..java.classes.java.lang.array import (
            Array, ByteArray, ObjectArray, ClassArray, StringArray, IntArray
        )
        from ..java.classes.java.lang.reflect.constructor import Constructor
        from ..java.classes.java.lang.reflect.executable import Executable
        from ..java.classes.java.lang.reflect.field import Field, AccessibleObject
        from ..java.classes.java.lang.reflect.method import Method
        from ..java.classes.java.lang.reflect.proxy import Proxy
        from ..java.classes.java.io.file import File
        from ..java.classes.java.util.list import List as JavaList
        from ..java.classes.java.util.map import HashMap
        from ..java.classes.java.util.set_list import Set as JavaSet
        from ..java.classes.java.util.time_unit import TimeUnit

        base_classes = [
            Class, Object, String, System,
            Boolean, Integer, Long, Float,
            Array, ByteArray, ObjectArray, ClassArray, StringArray, IntArray,
            AccessibleObject, Executable, Constructor, Field, Method, Proxy,
            File, JavaList, HashMap, JavaSet, TimeUnit,
        ]

        for clz in base_classes:
            self.java_classloader.add_class(clz)

    def _init_syslibs(self) -> None:
        self.load_library("libc.so")

    def register_class(self, clazz: JavaClassDef) -> None:
        self.java_classloader.add_class(clazz)

    def register_classes(self, *classes: Any) -> None:
        for item in classes:
            if isinstance(item, (list, tuple, set)):
                for clz in item:
                    self.java_classloader.add_class(clz)
            else:
                self.java_classloader.add_class(item)

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
        return self.linker.load_module(filename, do_init, main_lib)

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
                "Unable to find symbol '%s' in module '%s'.",
                symbol_name,
                module.filename,
            )
            return None
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
                "Unable to find function '%s' in module '%s'.",
                function_name,
                module.filename,
            )
            return None
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

        saved_sp = self.mu.reg_read(self.registers.sp)

        if not self.scheduler._is_running:
            try:
                self.registers.write_args(self.java_vm, *argv)
                self.scheduler.exec(addr)
                return self.mu.reg_read(self.registers.ret)
            finally:
                self.mu.reg_write(self.registers.sp, saved_sp)
        else:
            saved_context = self.mu.context_save()
            interrupted_pc = self.mu.reg_read(self.registers.pc)

            try:
                smb = config.STOP_MEMORY_BASE
                self.registers.write_args(self.java_vm, *argv)
                self.mu.reg_write(self.registers.pc, addr)
                self.mu.reg_write(self.registers.lr, smb)

                logging.debug("Nested call to 0x%x from 0x%x", addr, interrupted_pc)
                self.mu.emu_start(addr, smb, 0, 0)

                if self.mu.reg_read(self.registers.pc) != smb:
                    logging.warning(
                        "Nested call to 0x%x was INTERRUPTED before completion!", addr
                    )

                return self.mu.reg_read(self.registers.ret)

            except UcError as e:
                logging.error("Crash in nested call to 0x%x: %s", addr, e)
                raise
            finally:
                self.mu.context_restore(saved_context)
                self.mu.reg_write(self.registers.sp, saved_sp)

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
        if res is None:
            return None

        off = 32 if self.arch == emu_const.ARCH_ARM32 else 64
        res_high = self.registers.v_reg_1

        return (res_high << off) | res