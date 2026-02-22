from .base_sym import BaseSymbolHooks

from typing import TYPE_CHECKING

import logging
import random
from unicorn.arm_const import *

from unicorn import *

from ...java.helpers.native_method import native_method
from ...utils import memory_helpers


if TYPE_CHECKING:
    from unicorn import Uc
    from ...emulator import Emulator

logger = logging.getLogger(__name__)

# actually, i think most hooks is not needed anymore here.
# but i leave this section

class LibCSymbolHooks(BaseSymbolHooks):

    def __init__(self, emu: 'Emulator'):
        super().__init__(emu)

        self._emu: 'Emulator' = emu
        
        self._func_table = {
        "__stack_chk_fail": self.stack_check_fail, # also try abort hook
        # "__system_property_get": self.system_property_get,
        # "pthread_create": self.pthread_create,
        # "pthread_once": self.pthread_once,
        # "pthread_detach": self.pthread_detach,
        "abort": self.abort,
        # "newlocale": self.newlocale,
        # "rand": self.rand,
        # "swprintf": self.swprintf,
        
        # "malloc": self.malloc,
        # "free": self.free,
        # "calloc": self.calloc,
        # "realloc": self.realloc,
        # "memalign": self.memalign,
        
        # "pthread_mutex_lock": self.pthread_mutex_lock,
        # "__aeabi_memclr": self.memclr,
        # "__aeabi_memset": self.memset,
    }

        self.global_func_table.update(self._func_table)


    # @native_method
    # def pthread_mutex_lock(self, uc, mutex):
    #     print("LICK MY BALLS")
    #     return 0

    @native_method
    def stack_check_fail(self, uc):
        raise RuntimeError("__stack_chk_fail called!!!")

    @native_method
    def malloc(self, uc, size):
        if size <= 0: return 0
        return self._emu.memory.map(0, size)
    
    @native_method
    def free(self, uc, ptr):
        if ptr == 0: return 0
        self._emu.memory.unmap(ptr)
        return 0

    @native_method
    def calloc(self, uc, nmemb, size):
        total = nmemb * size
        ptr = self.malloc(uc, total)
        if ptr:
            self._emu.mu.mem_write(ptr, b'\x00' * total)
        return ptr

    @native_method
    def realloc(self, uc, ptr, size):
        if ptr == 0: return self.malloc(uc, size)
        if size == 0: 
            self.free(uc, ptr)
            return 0
        
        old_size = self._emu.memory.get_size(ptr)
        
        if size <= old_size:
            return ptr
            
        new_ptr = self.malloc(uc, size)
        if new_ptr:
            data = self._emu.mu.mem_read(ptr, old_size)
            self._emu.mu.mem_write(new_ptr, data)
            self.free(uc, ptr)
        return new_ptr

    @native_method
    def memalign(self, uc, alignment, size):
        return self.malloc(uc, size)

    @native_method
    def memclr(self, uc, ptr, size):
        self._emu.mu.mem_write(ptr, b'\x00' * size)
        return 0

    @native_method
    def memset(self, uc, ptr, value, size):
        self._emu.mu.mem_write(ptr, bytes([value]) * size)
        return 0


    @native_method
    def system_property_get(self, uc: 'Uc', name_ptr: int, buf_ptr: int):
        #debug_utils.dump_registers(self._emu, sys.stdout)
        name = memory_helpers.read_utf8(uc, name_ptr)

        if name in self._emu.system_properties:
            p = self._emu.system_properties[name]
            nread = len(p)
            memory_helpers.write_utf8(uc, buf_ptr, p)
            return nread
        else:
            print ('%s was not found in system_properties dictionary.' % name)
        #
        return 0

    @native_method
    def abort(self, uc):
        raise RuntimeError("abort called!!!")
    #

    @native_method
    def pthread_once(self, uc: 'Uc', once_control_ptr: int, init_routine: int):
        state = int.from_bytes(uc.mem_read(once_control_ptr, 4), 'little')
        if state == 0:
            uc.mem_write(once_control_ptr, b'\x01\x00\x00\x00')
            logger.debug(f"[*] pthread_once: calling init_routine at {hex(init_routine)}")
            self._emu.call_native(init_routine)
        return 0

    @native_method
    def pthread_create(self, uc: 'Uc', pthread_t_ptr: int, attr: int, start_routine: int, arg: int):
        logging.warning("pthread_create called start_routine [0x%08X]"%(start_routine,))
        #pthread_t结构体实际上只是一个long
        uc.mem_write(pthread_t_ptr, int(self.__thread_id).to_bytes(self._emu.get_ptr_size(), byteorder='little'))
        self.__thread_id = self.__thread_id + 1
        return 0
    #

    @native_method
    def rand(self, uc):
        #这个函数实现同random，但4.4的libc没有这个符号
        logging.info("rand call")
        r = random.randint(0, 0xFFFFFFFF)
        return r
    #

    @native_method
    def newlocale(self, uc):
        #4.4的libc太旧没有这个函数，先这样绕过
        logging.info("newlocale call return 0 skip")
        return 0
    #

    def nop(self, name):
        @native_method
        def nop_inside(emu):
            raise NotImplementedError('Symbol hook not implemented %s' % name)
        return nop_inside
    #

    @native_method
    def pthread_join(self, uc, pthread_t, retval):
        return 0
    #

    @native_method
    def pthread_detach(self, uc, pthread_t):
        return 0
    #

    @native_method
    def dl_unwind_find_exidx(self, uc, pc, pcount_ptr):
        return 0
    #
