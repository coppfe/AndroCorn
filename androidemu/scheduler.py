import logging
import random

from collections import deque
from typing import TYPE_CHECKING, Dict, Set

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from .const.linux import *
from .data import mem_map as config
from .const import emu_const
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
        self.stack_base = 0
        self.stack_size = 0
        # self.is_forked_stack = False
        self.is_init = True
        self.is_main = False
        self.is_exit = False
        self.wakeup_time_us = -1 

class Scheduler:
    def __init__(self, emu: 'Emulator'):
        self.__emu = emu
        self.__mu = self.__emu.mu
        self.__pid = self.__emu.pcb.pid
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
        
        self.__wait_queue: Dict[int, Dict[int, int]] = {}
        self.__zombie_tasks: Dict[int, int] = {}

        is_arm32 = self.__emu.arch == emu_const.ARCH_ARM32

        self._reg_pc  = UC_ARM_REG_PC if is_arm32 else UC_ARM64_REG_PC
        self._reg_sp  = UC_ARM_REG_SP if is_arm32 else UC_ARM64_REG_SP
        self._reg_lr  = UC_ARM_REG_LR if is_arm32 else UC_ARM64_REG_X30
        self._reg_ret = UC_ARM_REG_R0 if is_arm32 else UC_ARM64_REG_X0
        self._reg_tls = UC_ARM_REG_C13_C0_3 if is_arm32 else UC_ARM64_REG_TPIDR_EL0
        self._reg_cpsr = UC_ARM_REG_CPSR if is_arm32 else None

        if is_arm32:
            self.__regs_list = [
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                UC_ARM_REG_R12, UC_ARM_REG_LR
            ]
        else:
            self.__regs_list = [
                UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,
                UC_ARM64_REG_X4,  UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,
                UC_ARM64_REG_X8,  UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11,
                UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
                UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
                UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
                UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
                UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30
            ]

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

    def __find_free_region(self, size, start_search):
        page_size = 0x1000
        size = (size + page_size - 1) & ~(page_size - 1)
        
        regions = sorted(self.__mu.mem_regions())
        
        current_addr = start_search
        for begin, end, prot in regions:
            if begin > current_addr and (begin - current_addr) >= size:
                return current_addr
            if end + 1 > current_addr:
                current_addr = (end + 1 + page_size - 1) & ~(page_size - 1)
        
        return current_addr

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
        t = self.__create_task(tid, self.__mu.reg_read(self._reg_sp), None, True, 0)
        t.entry = entry_point 
        self.__tasks_map[tid] = t
        self.__ready_queue.append(tid)

    def fork_task(self):
        parent_tid = self.__cur_tid
        child_tid = self.__next_sub_tid
        self.__next_sub_tid += 1
        regs = self.__regs_list

        parent_ctx = self.__mu.context_save()
        parent_sp = self.__mu.reg_read(self._reg_sp)
        p_stack_base = config.STACK_ADDR
        p_stack_end = config.STACK_ADDR + config.STACK_SIZE - 1
                
        if not (p_stack_base <= parent_sp <= p_stack_end):
            p_stack_base = parent_sp & ~0xFFF
            p_stack_end = p_stack_base + 0x1000 - 1

        start_read = max(p_stack_base, parent_sp - 0x1000)
        used_stack_size = (p_stack_end + 1) - start_read
        
        stack_data = bytearray(self.__mu.mem_read(start_read, used_stack_size))

        stack_size = (used_stack_size + 0xFFF) & ~0xFFF
        stack_size = max(0x100000, stack_size)
        
        child_stack_base = self.__find_free_region(stack_size, config.CHILD_STACK_ADDR)
        self.__mu.mem_map(child_stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE)
        
        child_stack_top = child_stack_base + stack_size
        child_sp = child_stack_top - ((p_stack_end + 1) - parent_sp)
        
        # Deep Stack Patch
        stack_offset = child_stack_top - (p_stack_end + 1)

        is_arm32 = self.__emu.arch == emu_const.ARCH_ARM32
        ptr_size = 4 if is_arm32 else 8
        # fmt = "<I" if is_arm32 else "<Q"

        for i in range(0, len(stack_data) - ptr_size + 1, ptr_size):
            val = int.from_bytes(stack_data[i:i+ptr_size], 'little')
            if p_stack_base <= val <= p_stack_end:
                new_val = val + stack_offset
                stack_data[i:i+ptr_size] = new_val.to_bytes(ptr_size, 'little')

        self.__mu.mem_write(child_stack_top - used_stack_size, bytes(stack_data))
        self.__mu.reg_write(self._reg_sp, child_sp)

        for reg in regs:
            val = self.__mu.reg_read(reg)
            if p_stack_base <= val <= p_stack_end:
                self.__mu.reg_write(reg, val + stack_offset)

        self.__clear_reg0() # child always returns 0
        child_ctx = self.__mu.context_save()

        self.__mu.context_restore(parent_ctx)

        t = self.__create_task(
            child_tid, 
            child_sp, 
            child_ctx, 
            False, 
            self.__tasks_map[parent_tid].tls_ptr
        )
        t.stack_base = child_stack_base
        t.stack_size = stack_size
        
        self.__tasks_map[child_tid] = t
        self.__ready_queue.append(child_tid)

        self.__emu.pcb.virtual_files.clone_for_task(parent_tid, child_tid, share_table=False)

        logging.debug("Fork: Parent %d -> Child %d (Stack: {0x%x} - {0x%x})", parent_tid, child_tid, child_stack_base, child_stack_top)

        self.yield_task()
        return child_tid
    
    def add_sub_task(self, stack_ptr, tls_ptr=0):
        tid = self.__next_sub_tid
        self.__next_sub_tid += 1
        
        parent_ctx = self.__mu.context_save()
        
        self.__set_sp(stack_ptr)
        if tls_ptr != 0:
            self.__set_tls(tls_ptr)
        self.__clear_reg0()
        child_ctx = self.__mu.context_save()
        
        self.__mu.context_restore(parent_ctx)
        
        t = self.__create_task(tid, stack_ptr, child_ctx, False, tls_ptr)
        self.__tasks_map[tid] = t
        self.__ready_queue.append(tid)
        
        self.__emu.pcb.virtual_files.clone_for_task(self.__cur_tid, tid, share_table=True)
        
        return tid
    
    def wait4_task(self, target_tid, wstatus_ptr, options=0):
        WNOHANG = 1
        
        if target_tid == -1:
            if self.__zombie_tasks:
                z_tid, exit_code = next(iter(self.__zombie_tasks.items()))
                if wstatus_ptr != 0:
                    status_val = (exit_code & 0xFF) << 8
                    try: self.__mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                    except Exception: pass
                del self.__zombie_tasks[z_tid]
                return z_tid
            elif len(self.__tasks_map) > 1:
                if options & WNOHANG:
                    return 0
                
                parent_tid = self.__cur_tid
                waiting_parents = self.__wait_queue.setdefault(-1, {})
                waiting_parents[parent_tid] = wstatus_ptr
                self.__blocking_set.add(parent_tid)
                self.__tasks_map[parent_tid].wakeup_time_us = -1
                self.yield_task()
                return 0
            else:
                return -ECHILD

        # TID is "sleeped"
        if target_tid in self.__zombie_tasks:
            exit_code = self.__zombie_tasks[target_tid]
            if wstatus_ptr != 0:
                status_val = (exit_code & 0xFF) << 8
                try: self.__mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                except Exception: pass
            del self.__zombie_tasks[target_tid]
            return target_tid

        # TID Running
        if target_tid in self.__tasks_map:
            if options & WNOHANG:
                return 0 
                
            parent_tid = self.__cur_tid
            waiting_parents = self.__wait_queue.setdefault(target_tid, {})
            waiting_parents[parent_tid] = wstatus_ptr
            self.__blocking_set.add(parent_tid)
            self.__tasks_map[parent_tid].wakeup_time_us = -1
            self.yield_task()
            return 0

        return -ECHILD

    def get_current_tid(self):
        return self.__cur_tid

    def exit_current_task(self):
        if self.__cur_tid in self.__tasks_map:
            self.__tasks_map[self.__cur_tid].is_exit = True
            self.__tid_2_remove.add(self.__cur_tid)
        self.__emu.pcb.virtual_files.remove_task(self.__cur_tid)
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
            logging.debug("%s futex_wake unblocked tid %s", cur_tid, tid)
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

            if task.is_main and task.is_init:
                start_pos = task.entry
                task.is_init = False
            else:
                self.__mu.context_restore(task.context)


                start_pos = self.__get_interrupted_entry()
                task.is_init = False

            try:
                self.__mu.emu_start(start_pos, self.__stop_pos, 0, 0)
            except UcError as e:
                logging.error("Crash in thread %s at 0x%x: %s", tid, start_pos, e)
                raise

            task.context = self.__mu.context_save()
            self.__emu.time_manager.advance_time(random.randint(50, 200))

            pc = self.__get_pc()
            
            if pc == self.__stop_pos or task.is_exit:
                exit_code = self.__mu.reg_read(self._reg_ret)
                self.__zombie_tasks[tid] = exit_code
                self.__tid_2_remove.add(tid)
                
                reaped = False
                
                if tid in self.__wait_queue:
                    for parent_tid, wstatus_ptr in self.__wait_queue[tid].items():
                        if parent_tid in self.__blocking_set:
                            self.__blocking_set.remove(parent_tid)
                            self.__ready_queue.append(parent_tid)
                            
                            if wstatus_ptr != 0:
                                status_val = (exit_code & 0xFF) << 8
                                try: self.__mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                                except Exception: pass
                                
                            if parent_tid in self.__tasks_map:
                                p_task = self.__tasks_map[parent_tid]
                                self.__mu.context_restore(p_task.context)
                                self.__mu.reg_write(self._reg_ret, tid)
                                p_task.context = self.__mu.context_save()
                                
                    del self.__wait_queue[tid]
                    reaped = True
                    
                elif -1 in self.__wait_queue and self.__wait_queue[-1]:
                    while self.__wait_queue[-1]:
                        parent_tid, wstatus_ptr = self.__wait_queue[-1].popitem()
                        if parent_tid in self.__blocking_set:
                            self.__blocking_set.remove(parent_tid)
                            self.__ready_queue.append(parent_tid)
                            
                            if wstatus_ptr != 0:
                                status_val = (exit_code & 0xFF) << 8
                                try: self.__mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                                except Exception: pass
                                
                            if parent_tid in self.__tasks_map:
                                p_task = self.__tasks_map[parent_tid]
                                self.__mu.context_restore(p_task.context)
                                self.__mu.reg_write(self._reg_ret, tid)
                                p_task.context = self.__mu.context_save()
                            reaped = True
                            break
                    if not self.__wait_queue[-1]:
                        del self.__wait_queue[-1]
                
                if reaped:
                    del self.__zombie_tasks[tid]

            elif tid not in self.__blocking_set:
                self.__ready_queue.append(tid)

            for t_id in list(self.__tid_2_remove): 
                task_to_remove = self.__tasks_map.pop(t_id, None)
                
                if task_to_remove and not task_to_remove.is_main:
                    if task_to_remove.stack_base != 0:
                        try:
                            self.__mu.mem_unmap(task_to_remove.stack_base, task_to_remove.stack_size)
                            logging.debug("Unmapped stack for TID %d at 0x%x", t_id, task_to_remove.stack_base)
                        except Exception as e:
                            logging.error("Failed to unmap stack for TID %d: %s", t_id, e)

            self.__tid_2_remove.clear()