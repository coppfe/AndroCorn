import logging
import random
from collections import deque
from typing import TYPE_CHECKING, Dict, Set

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from .data import mem_map as config
from .const import emu_const
from .utils.memory.mem_monitor import MemoryMonitor
from .java.helpers.native_method import native_write_args

if TYPE_CHECKING:
    from .emulator import Emulator

class Task:
    def __init__(self):
        self.entry = 0
        self.context = None
        self.tid = 0
        self.init_stack_ptr = 0
        self.tls_ptr = 0
        self.is_init = True
        self.is_main = False
        self.is_exit = False
        self.wakeup_time_us = -1 

class Scheduler:
    def __init__(self, emu: 'Emulator'):
        self.__emu = emu
        self.__mu = self.__emu.mu
        self.__pid = self.__emu.pcb.get_pid()
        self.__next_sub_tid = self.__pid + 1
        
        self.__tasks_map: Dict[int, Task] = {} 
        self.__ready_queue: deque = deque()
        self.__tid_2_remove = set()
        self.__cur_tid = 0
        self.__is_running = False

        self.__emu.memory.map(config.STOP_MEMORY_BASE, config.STOP_MEMORY_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.__stop_pos = config.STOP_MEMORY_BASE

        self.__futex_blocking_map = {}
        self.__blocking_set: Set[int] = set()

        self.mem_monitor = MemoryMonitor(emu)

        is_arm32 = self.__emu.arch == emu_const.ARCH_ARM32
        self._reg_pc  = UC_ARM_REG_PC if is_arm32 else UC_ARM64_REG_PC
        self._reg_sp  = UC_ARM_REG_SP if is_arm32 else UC_ARM64_REG_SP
        self._reg_lr  = UC_ARM_REG_LR if is_arm32 else UC_ARM64_REG_X30
        self._reg_ret = UC_ARM_REG_R0 if is_arm32 else UC_ARM64_REG_X0
        self._reg_tls = UC_ARM_REG_C13_C0_3 if is_arm32 else UC_ARM64_REG_TPIDR_EL0
        self._reg_cpsr = UC_ARM_REG_CPSR if is_arm32 else None

    def __get_pc(self): return self.__mu.reg_read(self._reg_pc)
    def __set_sp(self, sp): self.__mu.reg_write(self._reg_sp, sp)
    def __set_tls(self, tls_ptr): self.__mu.reg_write(self._reg_tls, tls_ptr)
    def __clear_reg0(self): self.__mu.reg_write(self._reg_ret, 0)

    def __get_interrupted_entry(self):
        pc = self.__get_pc()
        if self._reg_cpsr is not None:
            cpsr = self.__mu.reg_read(self._reg_cpsr)
            if cpsr & (1 << 5): pc |= 1
        return pc

    def __create_task(self, tid, stack_ptr, context, is_main, tls_ptr):
        t = Task()
        t.tid = tid
        t.init_stack_ptr = stack_ptr
        t.context = context
        t.is_main = is_main
        t.tls_ptr = tls_ptr
        return t

    def __set_main_task(self, entry_point):
        tid = self.__pid
        t = self.__create_task(tid, 0, None, True, 0)
        t.entry = entry_point 
        self.__tasks_map[tid] = t
        self.__ready_queue.append(tid)

    def get_current_tid(self):
        return self.__cur_tid

    def add_sub_task(self, stack_ptr, tls_ptr=0):
        tid = self.__next_sub_tid
        ctx = self.__mu.context_save()
        t = self.__create_task(tid, stack_ptr, ctx, False, tls_ptr)
        self.__tasks_map[tid] = t
        self.__ready_queue.append(tid)
        self.__next_sub_tid += 1
        return tid

    def exit_current_task(self):
        if self.__cur_tid in self.__tasks_map:
            self.__tasks_map[self.__cur_tid].is_exit = True
            self.__tid_2_remove.add(self.__cur_tid)
        self.yield_task()

    def yield_task(self):
        self.__mu.emu_stop()

    def sleep(self, ms):
        tid = self.__cur_tid
        self.__blocking_set.add(tid)
        curr_time = self.__emu.time_manager.get_current_time_us()
        self.__tasks_map[tid].wakeup_time_us = curr_time + int(ms * 1000)
        self.yield_task()

    def futex_wait(self, futex_ptr, timeout=-1):
        block_set = self.__futex_blocking_map.setdefault(futex_ptr, set())
        tid = self.__cur_tid
        block_set.add(tid)
        self.__blocking_set.add(tid)
        if timeout > 0:
            curr_time = self.__emu.time_manager.get_current_time_us()
            self.__tasks_map[tid].wakeup_time_us = curr_time + int(timeout * 1000)
        else:
            self.__tasks_map[tid].wakeup_time_us = -1
        self.yield_task()

    def futex_wake(self, futex_ptr):
        cur_tid = self.__cur_tid
        block_set = self.__futex_blocking_map.get(futex_ptr)
        if block_set and len(block_set) > 0:
            tid = block_set.pop()
            if tid in self.__blocking_set: self.__blocking_set.remove(tid)
            if tid in self.__tasks_map:
                self.__tasks_map[tid].wakeup_time_us = -1 
                self.__ready_queue.append(tid)
            logging.debug(f"{cur_tid} futex_wake unblocked tid {tid}")
            return True
        return False

    def exec(self, main_entry, clear_task_when_return=True):
        if self.__is_running:
            raise RuntimeError("Scheduler is already running!")
        
        self.__is_running = True
        try:
            self.__set_main_task(main_entry)
            self.__mu.reg_write(self._reg_lr, self.__stop_pos)
            self.__run_scheduler_loop()
        finally:
            self.__is_running = False
            logging.debug("Main scheduler finished.")
            if clear_task_when_return:
                self.__tasks_map.clear()
                self.__ready_queue.clear()
                self.__blocking_set.clear()

    def call_native(self, addr, *args):
        if not self.__is_running:
            native_write_args(self.__emu, *args)
            self.exec(addr)
            return self.__mu.reg_read(self._reg_ret)
        else:
            raise NotImplementedError("Nested calls are temporarily disabled.")

    def __run_scheduler_loop(self):
        while self.__pid in self.__tasks_map:
            current_time = self.__emu.time_manager.get_current_time_us()
            woken_up =[]
            for tid in list(self.__blocking_set):
                if tid not in self.__tasks_map: 
                    self.__blocking_set.remove(tid)
                    continue
                t = self.__tasks_map[tid]
                if t.wakeup_time_us != -1 and current_time >= t.wakeup_time_us:
                    woken_up.append(tid)
            
            for tid in woken_up:
                self.__blocking_set.remove(tid)
                self.__tasks_map[tid].wakeup_time_us = -1
                self.__ready_queue.append(tid)

            if not self.__ready_queue:
                if self.__blocking_set:
                    valid_times = [self.__tasks_map[t].wakeup_time_us for t in self.__blocking_set if self.__tasks_map[t].wakeup_time_us != -1]
                    if valid_times:
                        self.__emu.time_manager.jump_to_time(min(valid_times))
                        continue
                    elif len(self.__tasks_map) == 1:
                        raise RuntimeError("Deadlock: Main thread waiting indefinitely.")
                    else:
                        break
                else:
                    break

            tid = self.__ready_queue.popleft()
            if tid not in self.__tasks_map or tid in self.__blocking_set: continue
            
            task = self.__tasks_map[tid]
            self.__cur_tid = tid
            self.__emu.pcb._current_tid = tid 

            if task.is_init:
                start_pos = task.entry if task.is_main else self.__get_interrupted_entry()
                if not task.is_main:
                    self.__mu.context_restore(task.context)
                    self.__set_sp(task.init_stack_ptr)
                    if task.tls_ptr: self.__set_tls(task.tls_ptr)
                    self.__clear_reg0() # return 0 for child thread
                task.is_init = False
            else:
                self.__mu.context_restore(task.context)
                start_pos = self.__get_interrupted_entry()

            try:
                self.__mu.emu_start(start_pos, self.__stop_pos, 0, 0)
            except UcError as e:
                logging.error(f"Crash in thread {tid} at {hex(self.__get_pc())}: {e}")
                raise

            task.context = self.__mu.context_save()
            self.__emu.time_manager.advance_time(random.randint(50, 200))

            pc = self.__get_pc()
            
            if pc == self.__stop_pos or task.is_exit:
                self.__tid_2_remove.add(tid)
            elif tid not in self.__blocking_set:
                self.__ready_queue.append(tid)

            for t in self.__tid_2_remove: 
                self.__tasks_map.pop(t, None)
            self.__tid_2_remove.clear()