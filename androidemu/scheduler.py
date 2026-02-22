import logging
import time
import binascii

from typing import TYPE_CHECKING

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from . import config
from .const import emu_const
from .utils import memory_helpers
from .utils.mem_monitor import MemoryMonitor

if TYPE_CHECKING:
    from .emulator import Emulator

class Task:
    def __init__(self):
        self.entry = 0
        self.context = None
        self.tid = 0
        self.init_stack_ptr = 0
        self.tls_ptr = 0
        #是否第一次调用
        self.is_init = True
        self.is_main = False
        self.is_exit = False
        #the time ts for prev halt, in ms
        self.halt_ts = -1
        #the timeout for blocking -1 is infinte
        self.blocking_timeout = -1
    #
#

class Scheduler:


    def __init__(self, emu: 'Emulator'):
        self.__emu = emu
        self.__mu = self.__emu.mu
        self.__pid = self.__emu.get_pcb().get_pid()
        self.__next_sub_tid = self.__pid + 1
        self.__tasks_map = {} # in python 3.7+ dict is ordered
        self.__defer_task_map = {}
        self.__tid_2_remove = set()
        self.__cur_tid = 0

        self.__emu.memory.map(config.STOP_MEMORY_BASE, config.STOP_MEMORY_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.__stop_pos = config.STOP_MEMORY_BASE

        #blocking futex ptr to thread lists, 
        #记录在futex中等待的任务id
        self.__futex_blocking_map = {}
        self.pending_logs = {}
        #just record all blocking tid
        self.__blocking_set = set()

        self.loggingvalues = {}

        self.mem_monitor = MemoryMonitor(emu)
    #

    def __get_pc(self):
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            pc = self.__emu.mu.reg_read(UC_ARM_REG_PC)
            return pc
        else:
            return self.__emu.mu.reg_read(UC_ARM64_REG_PC)
        #
    #

    def __clear_reg0(self):
        
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            self.__mu.reg_write(UC_ARM_REG_R0, 0)
        else:
            self.__mu.reg_write(UC_ARM64_REG_X0, 0)
        #
    #

    def __set_sp(self, sp):
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            self.__emu.mu.reg_write(UC_ARM_REG_SP, sp)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_SP, sp)
        #
    #

    def __set_tls(self, tls_ptr):
        if (self.__emu.get_arch() ==  emu_const.ARCH_ARM32):
            self.__emu.mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls_ptr)
    #

    def __get_interrupted_entry(self):
        pc = self.__get_pc()
        if (self.__emu.get_arch() == emu_const.ARCH_ARM32):
            cpsr = self.__emu.mu.reg_read(UC_ARM_REG_CPSR)
            if (cpsr & (1<<5)):
                pc = pc | 1
            #
        #
        return pc
    #

    def __create_task(self, tid, stack_ptr, context, is_main, tls_ptr):
        t = Task()
        t.tid = tid
        t.init_stack_ptr = stack_ptr
        t.context = context
        t.is_main = is_main
        t.tls_ptr = tls_ptr
        return t
    #

    def __set_main_task(self):
        tid = self.__emu.get_pcb().get_pid()
        if (tid in self.__tasks_map):
            raise RuntimeError("set_main_task fail for main task %d exist!!!"%tid)
        #
        t = self.__create_task(tid, 0, None, True, 0)
        self.__tasks_map[tid] = t
    #

    def sleep(self, ms):
        tid = self.__cur_tid
        self.__blocking_set.add(tid)
        self.__tasks_map[tid].blocking_timeout = ms
        self.yield_task()
    #

    def futex_wait(self, futex_ptr, timeout=-1):
        block_set = None
        if futex_ptr in self.__futex_blocking_map:
            block_set = self.__futex_blocking_map[futex_ptr]
        #
        else:
            block_set = set()
            self.__futex_blocking_map[futex_ptr] = block_set
        #
        tid = self.get_current_tid()
        block_set.add(tid)
        self.__blocking_set.add(tid)
        self.__tasks_map[tid].blocking_timeout = timeout

        #handle out control flow
        self.yield_task()
    #

    def futex_wake(self, futex_ptr):
        cur_tid = self.get_current_tid()

        if (futex_ptr in self.__futex_blocking_map):
            block_set = self.__futex_blocking_map[futex_ptr]
            if len(block_set) > 0:
                tid = block_set.pop()
                self.__blocking_set.remove(tid)
                logging.debug("%d futex_wake tid %d waiting in futex_ptr 0x%08X is unblocked"%(cur_tid, tid, futex_ptr))
                return True
            else:
                logging.info("%d futex_wake unblock nobody waiting in futex ptr 0x%08X"%(cur_tid, futex_ptr))
                return False
        #
        else:
            logging.info("%d futex_wake unblock nobody waiting in futex ptr 0x%08X"%(cur_tid, futex_ptr))
            return False
        #
 
    #

    #创建子线程任务
    def add_sub_task(self, stack_ptr, tls_ptr=0):
        tid = self.__next_sub_tid
        #保存当前执行的上下文
        ctx = self.__emu.mu.context_save()
        t = self.__create_task(tid, stack_ptr, ctx, False, tls_ptr)
        self.__defer_task_map[tid] = t
        self.__next_sub_tid = self.__next_sub_tid + 1
        return tid
    #

    def get_current_tid(self):
        return self.__cur_tid
    #

    #yield the task.
    def yield_task(self):
        logging.debug("tid %d yield"%self.__cur_tid)
        self.__emu.mu.emu_stop()
    #
    
    def exit_current_task(self):
        self.__tasks_map[self.__cur_tid].is_exit = True
        self.__tid_2_remove.add(self.__cur_tid)
        self.yield_task()
    #

    #@params entry the main_thread entry_point
    def exec(self, main_entry, clear_task_when_return=True):
        self.__set_main_task()
        
        lr_reg = UC_ARM_REG_LR if self.__emu.get_arch() == emu_const.ARCH_ARM32 else UC_ARM64_REG_X30
        self.__emu.mu.reg_write(lr_reg, self.__stop_pos)

        while self.__pid in self.__tasks_map:

            for tid in reversed(list(self.__tasks_map.keys())):
                if tid not in self.__tasks_map:
                    continue
                
                task: Task = self.__tasks_map[tid]

                if tid in self.__blocking_set:
                    if not self._process_task_blocking(tid, task):
                        continue

                logging.debug(f"{tid} scheduling enter")
                self.__cur_tid = tid
                if task.is_init:
                    start_pos = main_entry if task.is_main else self.__get_interrupted_entry()
                    if not task.is_main:
                        self.__emu.mu.context_restore(task.context)
                        self.__set_sp(task.init_stack_ptr)
                        if task.tls_ptr:
                            self.__set_tls(task.tls_ptr)
                        self.__clear_reg0()
                    task.is_init = False
                else:
                    self.__emu.mu.context_restore(task.context)
                    start_pos = self.__get_interrupted_entry()
                
                try:
                    self.__emu.mu.emu_start(start_pos, self.__stop_pos, 0, 0)
                except Exception as e:
                    logging.error(f"Critical error in thread {tid} at FUN_{hex(start_pos)}: {e}")
                    raise
                
                task.halt_ts = int(time.time() * 1000)
                task.context = self.__emu.mu.context_save()

                if self.__get_pc() == self.__stop_pos or task.is_exit:
                    self.__tid_2_remove.add(tid)
                    logging.debug(f"{tid} scheduling exit")
                else:
                    logging.debug(f"{tid} scheduling paused")

            for tid in self.__tid_2_remove:
                self.__tasks_map.pop(tid, None)
            self.__tid_2_remove.clear()

            if self.__defer_task_map:
                self.__tasks_map.update(self.__defer_task_map)
                self.__defer_task_map.clear()

        logging.debug(f"Main thread tid [{self.__pid}] exit. Cleaning up.")
        if clear_task_when_return:
            self.__tasks_map.clear()

    def _process_task_blocking(self, tid: int, task: Task):
        is_only_task = len(self.__tasks_map) == 1

        if is_only_task:
            if task.blocking_timeout < 0:
                raise RuntimeError(f"Deadlock detected: only task {tid} is blocked indefinitely.")
            
            logging.debug(f"Only task {tid} is blocked. Sleeping for {task.blocking_timeout}ms")
            time.sleep(task.blocking_timeout / 1000.0)
            self.__blocking_set.remove(tid)
            return True

        if task.blocking_timeout > 0:
            elapsed = int(time.time() * 1000) - task.halt_ts
            if elapsed >= task.blocking_timeout:
                logging.debug(f"Task {tid} woke up by timeout")
                task.blocking_timeout = -1
                self.__blocking_set.remove(tid)
                return True
            
            logging.debug(f"Task {tid} is still sleeping ({elapsed}/{task.blocking_timeout}ms)")
            return False

        return False