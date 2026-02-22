import logging
import os
import time
import importlib
import inspect
import pkgutil
import sys
import os.path

from random import randint
from pathlib import Path

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from . import config
from . import pcb
from .const import emu_const
from .cpu.syscall_handlers import SyscallHandlers
from .cpu.syscall_hooks import SyscallHooks
from .hooker import Hooker
from .internal.linker import AndroidLinker
from .java.helpers.native_method import native_write_args
from .java.java_classloader import JavaClassLoader
from .java.java_vm import JavaVM
from .native.symbol_hooks import SymbolHooks
from .native.memory_syscall_handler import MemorySyscallHandler
from .native.memory_map import MemoryMap
from .internal.bionic.tls_factory import create_tls_backend
from .internal.bionic.tls_bionic import BionicTLS
from .vfs.file_system import VirtualFileSystem
from .vfs.virtual_file import VirtualFile
from .utils import misc_utils
from .utils import build_prop
from .scheduler import Scheduler
from .native_hook_utils import FuncHooker

from .java.java_class_def import JavaClassDef
from .java.constant_values import JAVA_NULL


#logger = logging.getLogger(__name__)
#logging.getLogger().setLevel(logging.DEBUG)
class Emulator:

    # https://github.com/unicorn-engine/unicorn/blob/8c6cbe3f3cabed57b23b721c29f937dd5baafc90/tests/regress/arm_fp_vfp_disabled.py#L15
    # 关于arm32 64 fp https://www.raspberrypi.org/forums/viewtopic.php?t=259802
    # https://www.cnblogs.com/pengdonglin137/p/3727583.html
    def __enable_vfp32(self):
        # MRC p15, #0, r1, c1, c0, #2
        # ORR r1, r1, #(0xf << 20)
        # MCR p15, #0, r1, c1, c0, #2
        # MOV r1, #0
        # MCR p15, #0, r1, c7, c5, #4
        # MOV r0,#0x40000000
        # FMXR FPEXC, r0
        code = '11EE501F'
        code += '41F47001'
        code += '01EE501F'
        code += '4FF00001'
        code += '07EE951F'
        code += '4FF08040'
        code += 'E8EE100A'
        # vpush {d8}
        code += '2ded028b'

        address = 0x1000
        mem_size = 0x1000
        code_bytes = bytes.fromhex(code)

        try:
            self.mu.mem_map(address, mem_size)
            self.mu.mem_write(address, code_bytes)
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)
            
            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_unmap(address, mem_size)
        #

    #
    #arm64
    '''
    mrs    x1, cpacr_el1
    mov    x0, #(3 << 20)
    orr    x0, x1, x0
    msr    cpacr_el1, x0
    '''
    def __enable_vfp64(self):
        #arm64 enable vfp
        x = 0
        x = self.mu.reg_read(UC_ARM64_REG_CPACR_EL1)
        x |= 0x300000; # set FPEN bit
        self.mu.reg_write(UC_ARM64_REG_CPACR_EL1, x)
    #

    def __add_classes(self):
        cur_file_dir = os.path.dirname(__file__)
        entry_file_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        #python 约定 package_name总是相对于入口脚本目录
        package_name = "androidemu"

        full_dirname = "%s/java/classes"%(cur_file_dir, )

        preload_classes = set()
        for importer, mod_name, c in pkgutil.iter_modules([full_dirname]):
            import_name = ".java.classes.%s"%mod_name
            m = importlib.import_module(import_name, package_name)
            #print(dir(m))
            clsList = inspect.getmembers(m, inspect.isclass)
            for _, clz in clsList:
                if (type(clz) == JavaClassDef):
                    preload_classes.add(clz)
                #
            #
        #
        for clz in preload_classes:
            self.java_classloader.add_class(clz)
        #

        #also add classloader as java class
        self.java_classloader.add_class(JavaClassLoader)
        
    #
    def __init__(self, vfs_root="vfs", config_path="androidemu/emu_cfg/default.json", vfp_inst_set=True, arch=emu_const.ARCH_ARM32, muti_task=False):
        # Unicorn.
        sys.stdout = sys.stderr
        #由于这里的stream只能改一次，为避免与fork之后的子进程写到stdout混合，将这些log写到stderr
        #FIXME:解除这种特殊的依赖
        # Since the stream here can only be changed once,
        # to avoid mixing stdout with output written by child processes after fork,
        # these logs are written to stderr.
        # FIXME: remove this dependency.

        self.config = config.Config(config_path)
        self.__arch = arch
        self.__support_muti_task = muti_task
        self.__pcb = pcb.Pcb()

        self.pid = self.__pcb.get_pid()
        self.tid = 0 # Init on Line:162
        self.uid = self.__pcb.get_uid()
        
        logging.info("process pid:%d"%self.pid)

        sp_reg = 0
        if arch == emu_const.ARCH_ARM32:
            self.__ptr_sz = 4
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            if vfp_inst_set:
                self.__enable_vfp32()
            #
            sp_reg = UC_ARM_REG_SP
            self.call_native = self.__call_native32
            self.call_native_return_2reg = self.__call_native_return_2reg32
        #
        elif arch == emu_const.ARCH_ARM64:
            self.__ptr_sz = 8
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            if vfp_inst_set:
                self.__enable_vfp64()
            # 
            sp_reg = UC_ARM64_REG_SP

            self.call_native = self.__call_native64
            self.call_native_return_2reg = self.__call_native_return_2reg64
        #
        else:
            raise RuntimeError("emulator arch=%d not support!!!"%arch)
        #
        self.tid = self.__pcb.get_tid(self.mu)

        self.__vfs_root = vfs_root

        #self.mu.mem_map(0x0, 0x00001000, UC_PROT_READ | UC_PROT_WRITE)

        #注意，原有缺陷，原来linker初始化没有完成init_tls部分，导致libc初始化有访问空指针而无法正常完成
        #而这里直接将0映射空间，,强行运行过去，因为R1刚好为0,否则会报memory unmap异常
        #最新版本已经解决这个问题，无需再这么映射

        # Note: there was a bug before — the linker initialization did not complete the init_tls step.
        # As a result, libc initialization accessed a null pointer and could not finish normally.
        # Here we map address 0 directly to force the execution to continue,
        # because R1 happens to be 0; otherwise a memory unmapped exception would occur.
        # This issue has been fixed in the latest version, so this mapping is no longer needed.

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

        self.memory = MemoryMap(self.mu, config.MAP_ALLOC_BASE, config.MAP_ALLOC_BASE+config.MAP_ALLOC_SIZE)

        # Stack.
        addr = self.memory.map(config.STACK_ADDR, config.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        self.mu.reg_write(sp_reg, (config.STACK_ADDR + config.STACK_SIZE) - 0x4000)
        #sp = self.mu.reg_read(sp_reg)
        #print ("stack addr %x"%sp)

        self.__sch = Scheduler(self)
        # CPU
        self.__syscall_handler = SyscallHandlers(self.mu, self.__sch, self.get_arch())

        # Hooker
        self.memory.map(config.BRIDGE_MEMORY_BASE, config.BRIDGE_MEMORY_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self._hooker = Hooker(self, config.BRIDGE_MEMORY_BASE, config.BRIDGE_MEMORY_SIZE)

        #syscalls
        self.mem_handler = MemorySyscallHandler(self, self.memory, self.__syscall_handler)
        self.syscall_hooks = SyscallHooks(self, self.config, self.__syscall_handler)
        self.vfs = VirtualFileSystem(self, vfs_root, self.config, self.__syscall_handler, self.memory)

        # JavaVM
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self._hooker)
        
        self.tls_state: 'BionicTLS' = create_tls_backend(self)

        # linker
        self.linker = AndroidLinker(self, self.__vfs_root)
        # Native

        self.func_hooker = FuncHooker(self)

        self.sym_hooks = SymbolHooks(self)

        self.__add_classes()

        #Hack 为jmethod_id指向的内存分配一块空间，抖音会将jmethodID强转，为的是绕过去
        self.memory.map(config.JMETHOD_ID_BASE, 0x2000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        if arch == emu_const.ARCH_ARM32:
            #映射常用的文件，cpu一些原子操作的函数实现地方
            path = "%s/system/lib/vectors"%vfs_root
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = VirtualFile("[vectors]", fd, path)
            self.memory.map(0xffff0000, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)

            #映射app_process，android系统基本特征
            path = "%s/system/bin/app_process32"%vfs_root
            sz = os.path.getsize(path)
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = VirtualFile("/system/bin/app_process32", fd, path)
            self.memory.map(0xab006000, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)
        #
        else:
            #映射app_process，android系统基本特征
            path = "%s/system/bin/app_process64"%vfs_root
            sz = os.path.getsize(path)
            fd = misc_utils.my_open(path, os.O_RDONLY)
            vf = VirtualFile("/system/bin/app_process64", fd, path)
            self.memory.map(0xab006000, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            os.close(fd)
        #
    #

    def get_vfs_root(self):
        return self.__vfs_root
    #

    def load_library(self, filename, do_init: bool = False, main_lib: bool = False):
        libmod = self.linker.load_module(filename, do_init, main_lib)
        return libmod
    #

    def call_symbol(self, module, symbol_name, *argv):
        symbol_addr = module.find_symbol(symbol_name)
        if symbol_addr is None:
            logging.error('Unable to find symbol \'%s\' in module \'%s\'.' % (symbol_name, module.filename))
            return

        return self.call_native(symbol_addr, *argv)
    #

    def __call_native32(self, addr, *argv):
        assert addr != None, "call addr is None, make sure your jni native function has registered by RegisterNative!"
        native_write_args(self, *argv)
        self.__sch.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM_REG_R0)
        return res
    #
    
    def __call_native64(self, addr, *argv):
        assert addr != None, "call addr is None, make sure your jni native function has registered by RegisterNative!"
        native_write_args(self, *argv)
        self.__sch.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM64_REG_X0)
        return res
    #


    #返回值8个字节,用两个寄存器保存
    def __call_native_return_2reg32(self, addr, *argv):
        res = self.__call_native32(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM_REG_R1)

        return (res_high << 32) | res
    #

    #返回值16个字节,用两个寄存器保存
    def __call_native_return_2reg64(self, addr, *argv):
        res = self.__call_native64(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM64_REG_X1)

        return (res_high << 64) | res
    #

    def get_arch(self):
        return self.__arch
    #

    def get_ptr_size(self):
        return self.__ptr_sz
    #

    def get_pcb(self):
        return self.__pcb
    #

    def get_schduler(self):
        return self.__sch
    #

    def get_muti_task_support(self):
        return self.__support_muti_task
    #
#