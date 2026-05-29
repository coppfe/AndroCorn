import logging
import random

from collections import deque
from typing import TYPE_CHECKING, Dict, Optional, Set

from unicorn import UcError, UC_PROT_READ, UC_PROT_WRITE

from ..const.linux import ECHILD
from ..data import mem_map as config

from ..types import ptr_t

if TYPE_CHECKING:
    from unicorn.unicorn import UcContext
    from unicorn import Uc
    from ..utils.memory.map import MemoryMap
    from ..core.state.time_manager import TimeManager
    from ..core.process.pcb import ProcessControlBlock
    from ..objects.registers import RegistersMapping
    from androidemu.core.state._global import GlobalContextMachine
    from androidemu.data.states.process import ProcessState

class Task:
    def __init__(self):
        self.entry = 0
        self.context: 'UcContext' = None # type: ignore
        self.tid = 0
        self.init_stack_ptr = 0
        self.tls_ptr = 0
        self.stack_base = 0
        self.stack_size = 0
        self.is_init = True
        self.is_main = False
        self.is_exit = False
        self.wakeup_time_us = -1 
        self.pending_regs: Dict[int, int] = {}

class Scheduler:
    """
    Scheduler class is working with threads and process so some syscalls are implemented here.
    Fully refactored to prevent JIT context corruption and memory breaches.
    """

    def __init__(self,
                mu: 'Uc',
                registers: 'RegistersMapping',
                memory: 'MemoryMap',
                pcb: 'ProcessControlBlock',
                time_manager: 'TimeManager',
                ctx: 'GlobalContextMachine'
                ):
                
        self._mu = mu
        self._pcb = pcb
        self._memory = memory
        self._ctx: 'ProcessState' = ctx # type: ignore
        self._time_manager = time_manager
        self._ptr_sz = ptr_t.size

        self._pid = self._ctx.pid
        self._next_sub_tid = self._pid + 1
        
        self._tasks_map: Dict[int, Task] = {} 
        self._ready_queue: deque = deque()
        self._tid_2_remove = set()
        self._is_running = False

        self._stop_pos = config.STOP_MEMORY_BASE
        
        self._futex_blocking_map = {}
        self._blocking_set: Set[int] = set()
        self._suspended_threads: Set[int] = set()
        
        self._wait_queue: Dict[int, Dict[int, int]] = {}
        self._zombie_tasks: Dict[int, int] = {}

        self._registers = registers

    def _get_interrupted_entry(self) -> int:
        pc = self._mu.reg_read(self._registers.pc)
        if self._registers.cpsr is not None:
            cpsr = self._mu.reg_read(self._registers.cpsr)
            if cpsr & (1 << 5): pc |= 1
        return pc

    def _create_task(self, tid, stack_ptr, context, is_main, tls_ptr) -> Task:
        t = Task()
        t.tid = tid
        t.init_stack_ptr = stack_ptr
        t.context = context
        t.is_main = is_main
        t.tls_ptr = tls_ptr
        return t
    
    def _set_main_task(self, entry_point, context: Optional['UcContext'] = None) -> None:
        tid = self._pid
        t = self._create_task(tid, self._mu.reg_read(self._registers.sp), None, True, 0)
        t.entry = entry_point 
        self._tasks_map[tid] = t
        self._ready_queue.append(tid)

    def fork_task(self) -> int:
        parent_tid = self._ctx.current_tid
        child_tid = self._next_sub_tid
        self._next_sub_tid += 1
        regs = self._registers.default

        parent_ctx = self._mu.context_save()
        parent_sp = self._mu.reg_read(self._registers.sp)
        p_stack_base = config.STACK_ADDR
        p_stack_end = config.STACK_ADDR + config.STACK_SIZE - 1
                
        if not (p_stack_base <= parent_sp <= p_stack_end):
            p_stack_base = parent_sp & ~0xFFF
            p_stack_end = p_stack_base + 0x1000 - 1

        start_read = max(p_stack_base, parent_sp - 0x1000)
        used_stack_size = (p_stack_end + 1) - start_read
        
        stack_data = bytearray(self._mu.mem_read(start_read, used_stack_size))

        stack_size = (used_stack_size + 0xFFF) & ~0xFFF
        stack_size = max(0x100000, stack_size)

        child_stack_base = self._memory.find_free_region(stack_size, config.CHILD_STACK_ADDR)
        self._memory.map(child_stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE)

        child_stack_top = child_stack_base + stack_size
        child_sp = child_stack_top - ((p_stack_end + 1) - parent_sp)
        
        stack_offset = child_stack_top - (p_stack_end + 1)

        ptr_size = self._ptr_sz

        aligned_len = (len(stack_data) // ptr_size) * ptr_size
        typecode = 'I' if ptr_size == 4 else 'Q'
        
        mv = memoryview(stack_data)[:aligned_len].cast(typecode)
        
        for i in range(len(mv)):
            val = mv[i]
            if p_stack_base <= val <= p_stack_end:
                mv[i] = val + stack_offset

        self._mu.mem_write(child_stack_top - used_stack_size, bytes(stack_data))
        self._mu.reg_write(self._registers.sp, child_sp)

        for reg in regs:
            val = self._mu.reg_read(reg)
            if p_stack_base <= val <= p_stack_end:
                self._mu.reg_write(reg, val + stack_offset)

        self._mu.reg_write(self._registers.ret, 0)
        child_ctx = self._mu.context_save()

        self._mu.context_restore(parent_ctx)

        t = self._create_task(
            child_tid, 
            child_sp, 
            child_ctx, 
            False, 
            self._tasks_map[parent_tid].tls_ptr
        )
        t.stack_base = child_stack_base
        t.stack_size = stack_size
        
        self._tasks_map[child_tid] = t
        self._ready_queue.append(child_tid)

        self._pcb.virtual_files.clone_for_task(parent_tid, child_tid, share_table=False)

        logging.debug("Fork: Parent %d -> Child %d (Stack: {0x%x} - {0x%x})", parent_tid, child_tid, child_stack_base, child_stack_top)

        self.yield_task()
        return child_tid
    
    def add_sub_task(self, stack_ptr: int, tls_ptr: int = 0) -> int:
        tid = self._next_sub_tid
        self._next_sub_tid += 1
        
        parent_ctx = self._mu.context_save()
        
        self._mu.reg_write(self._registers.sp, stack_ptr)
        if tls_ptr != 0:
            self._mu.reg_write(self._registers.tls, tls_ptr)
            
        self._mu.reg_write(self._registers.ret, 0)
        child_ctx = self._mu.context_save()
        
        self._mu.context_restore(parent_ctx)
        
        parent_tid = self._ctx.current_tid
        if parent_tid in self._tasks_map:
            parent_tls = self._tasks_map[parent_tid].tls_ptr
            if parent_tls != 0:
                try:
                    self._mu.reg_write(self._registers.tls, parent_tls)
                except Exception:
                    pass
        
        t = self._create_task(tid, stack_ptr, child_ctx, False, tls_ptr)
        t.is_init = False 
        self._tasks_map[tid] = t
        self._ready_queue.append(tid)
        
        self._pcb.virtual_files.clone_for_task(self._ctx.current_tid, tid, share_table=True)
        
        return tid
    
    def wait4_task(self, target_tid: int, wstatus_ptr: int, options: int = 0) -> int:
        WNOHANG = 1
        
        if target_tid == -1:
            if self._zombie_tasks:
                z_tid, exit_code = next(iter(self._zombie_tasks.items()))
                if wstatus_ptr != 0:
                    status_val = (exit_code & 0xFF) << 8
                    try: self._mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                    except Exception: pass
                del self._zombie_tasks[z_tid]
                return z_tid
            elif len(self._tasks_map) > 1:
                if options & WNOHANG:
                    return 0
                
                parent_tid = self._ctx.current_tid
                waiting_parents = self._wait_queue.setdefault(-1, {})
                waiting_parents[parent_tid] = wstatus_ptr
                self._blocking_set.add(parent_tid)
                self._tasks_map[parent_tid].wakeup_time_us = -1
                self.yield_task()
                return 0
            else:
                return -ECHILD

        if target_tid in self._zombie_tasks:
            exit_code = self._zombie_tasks[target_tid]
            if wstatus_ptr != 0:
                status_val = (exit_code & 0xFF) << 8
                try: self._mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                except Exception: pass
            del self._zombie_tasks[target_tid]
            return target_tid

        if target_tid in self._tasks_map:
            if options & WNOHANG:
                return 0 
                
            parent_tid = self._ctx.current_tid
            waiting_parents = self._wait_queue.setdefault(target_tid, {})
            waiting_parents[parent_tid] = wstatus_ptr
            self._blocking_set.add(parent_tid)
            self._tasks_map[parent_tid].wakeup_time_us = -1
            self.yield_task()
            return 0

        return -ECHILD

    def get_current_tid(self) -> int: return self._ctx.current_tid

    def exit_current_task(self) -> None:
        if self._ctx.current_tid in self._tasks_map:
            self._tasks_map[self._ctx.current_tid].is_exit = True
            self._tid_2_remove.add(self._ctx.current_tid)
        self._pcb.virtual_files.remove_task(self._ctx.current_tid)
        self.yield_task()

    def suspend_thread(self, tid: int) -> None:
        self._suspended_threads.add(tid)
        self.yield_task()

    def resume_thread(self, tid: int) -> None:
        if tid in self._suspended_threads:
            self._suspended_threads.remove(tid)
            if tid not in self._ready_queue and tid not in self._blocking_set:
                self._ready_queue.append(tid)

    def yield_task(self) -> None:
        self._mu.emu_stop()

    def sleep(self, ms: int) -> None:
        tid = self._ctx.current_tid
        self._blocking_set.add(tid)
        curr_time = self._time_manager.get_current_time_us()
        self._tasks_map[tid].wakeup_time_us = curr_time + int(ms * 1000)
        self.yield_task()

    def futex_wait(self, futex_ptr: int, timeout: int = -1) -> None:
        block_set = self._futex_blocking_map.setdefault(futex_ptr, set())
        tid = self._ctx.current_tid
        block_set.add(tid)
        self._blocking_set.add(tid)
        if timeout > 0:
            curr_time = self._time_manager.get_current_time_us()
            self._tasks_map[tid].wakeup_time_us = curr_time + int(timeout * 1000)
        else:
            self._tasks_map[tid].wakeup_time_us = -1
        
        self._tasks_map[tid].pending_regs[self._registers.ret] = 0
        self.yield_task()

    def futex_wake(self, futex_ptr) -> bool:
        cur_tid = self._ctx.current_tid
        block_set = self._futex_blocking_map.get(futex_ptr)
        if block_set and len(block_set) > 0:
            tid = block_set.pop()
            if tid in self._blocking_set: self._blocking_set.remove(tid)
            if tid in self._tasks_map:
                self._tasks_map[tid].wakeup_time_us = -1 
                self._ready_queue.append(tid)
            logging.debug("%s futex_wake unblocked tid %s", cur_tid, tid)
            return True
        return False

    def exec(self, main_entry: int, clear_task_when_return: bool = True) -> None:
        if self._is_running:
            raise RuntimeError("Scheduler is already running!")

        self._is_running = True
        try:
            self._set_main_task(main_entry)
            self._mu.reg_write(self._registers.lr, self._stop_pos)
            self._run_scheduler_loop()
        finally:
            self._is_running = False
            logging.debug("Main scheduler finished.")
            if clear_task_when_return:
                self._tasks_map.clear()
                self._ready_queue.clear()
                self._blocking_set.clear()
    
    def _run_scheduler_loop(self):
        while self._pid in self._tasks_map: # while task is active
            current_time = self._time_manager.get_current_time_us()
            woken_up =[] # woken tasks
            for tid in list(self._blocking_set):
                if tid not in self._tasks_map: 
                    self._blocking_set.remove(tid)
                    continue
                t = self._tasks_map[tid]
                if t.wakeup_time_us != -1 and current_time >= t.wakeup_time_us:
                    woken_up.append(tid)
            
            for tid in woken_up: # clean woken tasks
                self._blocking_set.remove(tid)
                self._tasks_map[tid].wakeup_time_us = -1
                self._ready_queue.append(tid)

            if not self._ready_queue: # no active tasks
                if self._blocking_set: # double check
                    # calculate nearest minimal time val and set it!
                    valid_times = [self._tasks_map[t].wakeup_time_us for t in self._blocking_set if self._tasks_map[t].wakeup_time_us != -1]
                    if valid_times:
                        self._time_manager.jump_to_time(min(valid_times))
                        continue
                    elif len(self._tasks_map) == 1:
                        raise RuntimeError("Deadlock: Main thread waiting indefinitely.")
                    else:
                        break
                else:
                    break

            tid = self._ready_queue.popleft()
            if tid not in self._tasks_map or tid in self._blocking_set: continue
            
            task = self._tasks_map[tid]
            self._ctx.current_tid = tid

            if task.is_main and task.is_init:
                start_pos = task.entry
                task.is_init = False
            else:
                self._mu.context_restore(task.context)
                
                if task.tls_ptr != 0:
                    try:
                        self._mu.reg_write(self._registers.tls, task.tls_ptr)
                    except Exception as e:
                        logging.warning("Failed to restore TLS during task switch to TID %d: %s", tid, e)
                            
                for reg_id, reg_val in task.pending_regs.items():
                    self._mu.reg_write(reg_id, reg_val)
                task.pending_regs.clear()
                
                start_pos = self._get_interrupted_entry()

            try:
                self._mu.emu_start(start_pos, self._stop_pos, 0, 0)
            except UcError as e:
                logging.error("Crash in thread %s at 0x%x: %s", tid, start_pos, e)
                raise

            task.context = self._mu.context_save()
            self._time_manager.advance_time(random.randint(50, 200))

            pc = self._mu.reg_read(self._registers.pc)
            
            if pc == self._stop_pos or task.is_exit:
                exit_code = self._mu.reg_read(self._registers.ret)
                self._zombie_tasks[tid] = exit_code
                self._tid_2_remove.add(tid)
                
                reaped = False
                
                if tid in self._wait_queue:
                    for parent_tid, wstatus_ptr in self._wait_queue[tid].items():
                        if parent_tid in self._blocking_set:
                            self._blocking_set.remove(parent_tid)
                            self._ready_queue.append(parent_tid)
                            
                            if wstatus_ptr != 0:
                                status_val: int = (exit_code & 0xFF) << 8
                                try: self._mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                                except Exception: pass
                                
                            if parent_tid in self._tasks_map:
                                self._tasks_map[parent_tid].pending_regs[self._registers.ret] = tid
                                
                    del self._wait_queue[tid]
                    reaped = True
                    
                elif -1 in self._wait_queue and self._wait_queue[-1]:
                    while self._wait_queue[-1]:
                        parent_tid, wstatus_ptr = self._wait_queue[-1].popitem()
                        if parent_tid in self._blocking_set:
                            self._blocking_set.remove(parent_tid)
                            self._ready_queue.append(parent_tid)
                            
                            if wstatus_ptr != 0:
                                status_val = (exit_code & 0xFF) << 8
                                try: self._mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                                except Exception: pass
                                
                            if parent_tid in self._tasks_map:
                                self._tasks_map[parent_tid].pending_regs[self._registers.ret] = tid
                                
                            reaped = True
                            break
                    if not self._wait_queue[-1]:
                        del self._wait_queue[-1]
                
                if reaped:
                    del self._zombie_tasks[tid]

            elif tid not in self._blocking_set and tid not in self._suspended_threads:
                self._ready_queue.append(tid)

            for t_id in list(self._tid_2_remove): 
                task_to_remove = self._tasks_map.pop(t_id, None)
                
                if task_to_remove and not task_to_remove.is_main:
                    if task_to_remove.stack_base != 0:
                        try:
                            self._mu.mem_unmap(task_to_remove.stack_base, task_to_remove.stack_size)
                            logging.debug("Unmapped stack for TID %d at 0x%x", t_id, task_to_remove.stack_base)
                        except Exception as e:
                            logging.error("Failed to unmap stack for TID %d: %s", t_id, e)

            self._tid_2_remove.clear()