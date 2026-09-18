import heapq
import logging
import random
from collections import deque
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

from unicorn import UC_PROT_READ, UC_PROT_WRITE, UcError

from ..const.linux import ECHILD, ETIMEDOUT
from ..data import layout as config

if TYPE_CHECKING:
    from unicorn import Uc
    from unicorn.unicorn import UcContext
    from ..core.pcb import ProcessControlBlock
    from ..core.registers import RegistersMapping
    from ..core.state.time_manager import TimeManager
    from ..kernel.fs.manager import VFSManager
    from ..utils.memory.map import MemoryMap


class Task:
    __slots__ = (
        "entry", "context", "tid", "init_stack_ptr",
        "tls_ptr", "stack_base", "stack_size",
        "is_init", "is_main", "is_exit",
        "wakeup_time_us", "pending_regs", "signal_contexts",
        "waiting_futex_addr"
    )

    def __init__(self):
        self.entry: int = 0
        self.context: Optional['UcContext'] = None
        self.tid: int = 0
        self.init_stack_ptr: int = 0
        self.tls_ptr: int = 0
        self.stack_base: int = 0
        self.stack_size: int = 0
        self.is_init: bool = True
        self.is_main: bool = False
        self.is_exit: bool = False
        self.wakeup_time_us: int = -1
        self.waiting_futex_addr: Optional[int] = None
        self.pending_regs: Dict[int, int] = {}
        self.signal_contexts: List['UcContext'] = []


class Scheduler:
    """
    Multithreading Scheduler for Unicorn.
    Features:
    - O(1) Time-Priority Sleep Queue (heapq)
    - POSIX-compliant Futex timeouts (-ETIMEDOUT)
    - Full VFS FD table cloning on thread/process fork
    - MemoryMap tracking for dead task stacks
    """

    def __init__(
        self,
        mu: 'Uc',
        registers: 'RegistersMapping',
        memory: 'MemoryMap',
        pcb: 'ProcessControlBlock',
        time_manager: 'TimeManager',
        vfs: Optional['VFSManager'] = None
    ):
        self._mu = mu
        self._pcb = pcb
        self._memory = memory
        self._time_manager = time_manager
        self._vfs = vfs
        self._registers = registers
        self._ptr_sz = 8 if getattr(registers, '_arch', 1) == 2 else 4

        self._pid = self._pcb.pid
        self._next_sub_tid = self._pid + 1

        self._tasks_map: Dict[int, Task] = {}
        self._ready_queue: deque[int] = deque()
        
        self._sleep_heap: List[Tuple[int, int]] = []
        
        self._tid_2_remove: Set[int] = set()
        self._is_running = False

        self._stop_pos = config.STOP_MEMORY_BASE

        self._futex_blocking_map: Dict[int, Set[int]] = {}
        self._blocking_set: Set[int] = set()
        self._suspended_threads: Set[int] = set()

        self._wait_queue: Dict[int, Dict[int, int]] = {}
        self._zombie_tasks: Dict[int, int] = {}

    def _get_interrupted_entry(self) -> int:
        pc = self._registers.v_pc
        if self._registers.flags is not None and self._registers.is_thumb():
            pc |= 1
        return pc

    def _create_task(self, tid: int, stack_ptr: int, context: Optional['UcContext'], is_main: bool, tls_ptr: int) -> Task:
        t = Task()
        t.tid = tid
        t.init_stack_ptr = stack_ptr
        t.context = context
        t.is_main = is_main
        t.tls_ptr = tls_ptr
        return t

    def _set_main_task(self, entry_point: int) -> None:
        tid = self._pid
        t = self._create_task(tid, self._registers.v_sp, None, True, 0)
        t.entry = entry_point
        self._tasks_map[tid] = t
        self._ready_queue.append(tid)

    def fork_task(self) -> int:
        parent_tid = self._pcb.current_tid
        child_tid = self._next_sub_tid
        self._next_sub_tid += 1
        regs = self._registers

        parent_ctx = self._mu.context_save()
        parent_sp = regs.v_sp
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
        regs.v_sp = child_sp

        for reg_id in regs.default:
            val = self._mu.reg_read(reg_id)
            if p_stack_base <= val <= p_stack_end:
                self._mu.reg_write(reg_id, val + stack_offset)

        regs.v_ret = 0
        child_ctx = self._mu.context_save()
        self._mu.context_restore(parent_ctx)

        t = self._create_task(
            child_tid,
            child_sp,
            child_ctx,
            False,
            self._tasks_map[parent_tid].tls_ptr if parent_tid in self._tasks_map else 0
        )
        t.stack_base = child_stack_base
        t.stack_size = stack_size

        self._tasks_map[child_tid] = t
        self._ready_queue.append(child_tid)

        if self._vfs:
            self._vfs.clone_task(parent_tid, child_tid, share_table=False)

        logging.debug("Fork: Parent %d -> Child %d (Stack: 0x%X - 0x%X)", parent_tid, child_tid, child_stack_base, child_stack_top)
        self.yield_task()
        return child_tid

    def add_sub_task(self, stack_ptr: int, tls_ptr: int = 0) -> int:
        tid = self._next_sub_tid
        self._next_sub_tid += 1
        regs = self._registers

        parent_ctx = self._mu.context_save()
        regs.v_sp = stack_ptr
        if tls_ptr != 0:
            regs.v_tls = tls_ptr

        regs.v_ret = 0
        child_ctx = self._mu.context_save()
        self._mu.context_restore(parent_ctx)

        parent_tid = self._pcb.current_tid
        if parent_tid in self._tasks_map:
            parent_tls = self._tasks_map[parent_tid].tls_ptr
            if parent_tls != 0:
                try:
                    regs.v_tls = parent_tls
                except Exception:
                    pass

        t = self._create_task(tid, stack_ptr, child_ctx, False, tls_ptr)
        t.is_init = False
        self._tasks_map[tid] = t
        self._ready_queue.append(tid)

        if self._vfs:
            self._vfs.clone_task(self._pcb.current_tid, tid, share_table=True)

        return tid

    def wait4_task(self, target_tid: int, wstatus_ptr: int, options: int = 0) -> int:
        WNOHANG = 1

        if target_tid == -1:
            if self._zombie_tasks:
                z_tid, exit_code = next(iter(self._zombie_tasks.items()))
                if wstatus_ptr != 0:
                    status_val = (exit_code & 0xFF) << 8
                    try:
                        self._mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                    except Exception:
                        pass
                del self._zombie_tasks[z_tid]
                return z_tid
            elif len(self._tasks_map) > 1:
                if options & WNOHANG:
                    return 0

                parent_tid = self._pcb.current_tid
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
                try:
                    self._mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                except Exception:
                    pass
            del self._zombie_tasks[target_tid]
            return target_tid

        if target_tid in self._tasks_map:
            if options & WNOHANG:
                return 0

            parent_tid = self._pcb.current_tid
            waiting_parents = self._wait_queue.setdefault(target_tid, {})
            waiting_parents[parent_tid] = wstatus_ptr
            self._blocking_set.add(parent_tid)
            self._tasks_map[parent_tid].wakeup_time_us = -1
            self.yield_task()
            return 0

        return -ECHILD

    def exit_current_task(self) -> None:
        tid = self._pcb.current_tid
        if tid in self._tasks_map:
            self._tasks_map[tid].is_exit = True
            self._tid_2_remove.add(tid)
            if self._vfs:
                self._vfs.remove_task(tid)
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
        tid = self._pcb.current_tid
        self._blocking_set.add(tid)
        curr_time = self._time_manager.get_current_time_us()
        wake_us = curr_time + int(ms * 1000)

        self._tasks_map[tid].wakeup_time_us = wake_us
        heapq.heappush(self._sleep_heap, (wake_us, tid))

        self.yield_task()

    def futex_wait(self, futex_ptr: int, timeout_ms: int = -1) -> None:
        tid = self._pcb.current_tid
        block_set = self._futex_blocking_map.setdefault(futex_ptr, set())
        block_set.add(tid)
        self._blocking_set.add(tid)

        task = self._tasks_map[tid]
        task.waiting_futex_addr = futex_ptr

        if timeout_ms > 0:
            curr_time = self._time_manager.get_current_time_us()
            wake_us = curr_time + int(timeout_ms * 1000)
            task.wakeup_time_us = wake_us
            heapq.heappush(self._sleep_heap, (wake_us, tid))
        else:
            task.wakeup_time_us = -1

        task.pending_regs[self._registers.ret] = 0
        self.yield_task()

    def futex_wake(self, futex_ptr: int) -> bool:
        cur_tid = self._pcb.current_tid
        block_set = self._futex_blocking_map.get(futex_ptr)
        if block_set:
            tid = block_set.pop()
            if tid in self._blocking_set:
                self._blocking_set.remove(tid)
            if tid in self._tasks_map:
                t = self._tasks_map[tid]
                t.wakeup_time_us = -1
                t.waiting_futex_addr = None
                t.pending_regs[self._registers.ret] = 0
                self._ready_queue.append(tid)
            logging.debug("%d futex_wake unblocked tid %d", cur_tid, tid)
            return True
        return False

    def exec(self, main_entry: int, clear_task_when_return: bool = True) -> None:
        if self._is_running:
            raise RuntimeError("Scheduler is already running!")

        self._is_running = True
        try:
            self._set_main_task(main_entry)
            self._registers.v_lr = self._stop_pos
            self._run_scheduler_loop()
        finally:
            self._is_running = False
            logging.debug("Main scheduler finished.")
            if clear_task_when_return:
                self._tasks_map.clear()
                self._ready_queue.clear()
                self._blocking_set.clear()
                self._sleep_heap.clear()
                self._futex_blocking_map.clear()

    def _update_sleeping_tasks(self) -> None:
        current_time = self._time_manager.get_current_time_us()

        while self._sleep_heap and self._sleep_heap[0][0] <= current_time:
            wake_us, tid = heapq.heappop(self._sleep_heap)
            
            if tid not in self._tasks_map:
                self._blocking_set.discard(tid)
                continue

            task = self._tasks_map[tid]
            if task.wakeup_time_us == wake_us and tid in self._blocking_set:
                self._blocking_set.remove(tid)
                task.wakeup_time_us = -1

                if task.waiting_futex_addr is not None:
                    futex_set = self._futex_blocking_map.get(task.waiting_futex_addr)
                    if futex_set:
                        futex_set.discard(tid)
                    task.waiting_futex_addr = None
                    task.pending_regs[self._registers.ret] = -ETIMEDOUT

                self._ready_queue.append(tid)

    def _handle_deadlock_or_idle(self) -> bool:
        if not self._blocking_set:
            return False

        while self._sleep_heap:
            next_wake_us, tid = self._sleep_heap[0]
            if tid in self._tasks_map and self._tasks_map[tid].wakeup_time_us == next_wake_us:
                self._time_manager.jump_to_time(next_wake_us)
                return True
            heapq.heappop(self._sleep_heap)

        if len(self._tasks_map) == 1 and self._pid in self._tasks_map:
            raise RuntimeError("Deadlock: Main thread is blocked indefinitely with no pending timers.")
        return False

    def _execute_task(self, task: Task) -> None:
        tid = task.tid

        if task.is_main and task.is_init:
            start_pos = task.entry
            task.is_init = False
        else:
            self._mu.context_restore(task.context)
            if task.tls_ptr != 0:
                try:
                    self._registers.v_tls = task.tls_ptr
                except Exception as e:
                    logging.warning("Failed to restore TLS for TID %d: %s", tid, e)

            for reg_id, reg_val in task.pending_regs.items():
                self._mu.reg_write(reg_id, reg_val)
            task.pending_regs.clear()

            start_pos = self._get_interrupted_entry()

        try:
            self._mu.emu_start(start_pos, self._stop_pos, 0, 0)
        except UcError as e:
            pos = self._registers.v_pc
            logging.error("Crash in thread %d at 0x%X: %s", tid, pos, e)
            raise

        task.context = self._mu.context_save()
        self._time_manager.advance_time(random.randint(50, 200))

    def _handle_task_post_execution(self, task: Task) -> None:
        tid = task.tid
        pc = self._registers.v_pc
        sigret_addr = config.SIGRET

        if pc == sigret_addr and task.signal_contexts:
            saved_ctx = task.signal_contexts.pop()
            self._mu.context_restore(saved_ctx)
            task.context = self._mu.context_save()
            self._ready_queue.append(tid)
            return

        if pc == self._stop_pos or task.is_exit:
            exit_code = self._registers.v_ret
            self._zombie_tasks[tid] = exit_code
            self._tid_2_remove.add(tid)
            self._reap_wait_queue(tid, exit_code)
        elif tid not in self._blocking_set and tid not in self._suspended_threads:
            self._ready_queue.append(tid)

    def _reap_wait_queue(self, tid: int, exit_code: int) -> None:
        reaped = False
        if tid in self._wait_queue:
            for parent_tid, wstatus_ptr in self._wait_queue[tid].items():
                self._unblock_wait_parent(parent_tid, wstatus_ptr, tid, exit_code)
            del self._wait_queue[tid]
            reaped = True
        elif -1 in self._wait_queue and self._wait_queue[-1]:
            while self._wait_queue[-1]:
                parent_tid, wstatus_ptr = self._wait_queue[-1].popitem()
                self._unblock_wait_parent(parent_tid, wstatus_ptr, tid, exit_code)
                reaped = True
                break
            if not self._wait_queue[-1]:
                del self._wait_queue[-1]

        if reaped:
            self._zombie_tasks.pop(tid, None)

    def _unblock_wait_parent(self, parent_tid: int, wstatus_ptr: int, child_tid: int, exit_code: int) -> None:
        if parent_tid in self._blocking_set:
            self._blocking_set.remove(parent_tid)
            self._ready_queue.append(parent_tid)
            if wstatus_ptr != 0:
                status_val = (exit_code & 0xFF) << 8
                try:
                    self._mu.mem_write(wstatus_ptr, status_val.to_bytes(4, "little"))
                except Exception:
                    pass
            if parent_tid in self._tasks_map:
                self._tasks_map[parent_tid].pending_regs[self._registers.ret] = child_tid

    def _cleanup_dead_tasks(self) -> None:
        for t_id in list(self._tid_2_remove):
            task_to_remove = self._tasks_map.pop(t_id, None)
            if task_to_remove and not task_to_remove.is_main:
                if task_to_remove.stack_base != 0:
                    self._memory.unmap(task_to_remove.stack_base, task_to_remove.stack_size)
                    logging.debug("Unmapped stack for TID %d at 0x%X", t_id, task_to_remove.stack_base)
        self._tid_2_remove.clear()

    def _run_scheduler_loop(self) -> None:
        while self._pid in self._tasks_map:
            self._update_sleeping_tasks()

            if not self._ready_queue:
                if self._handle_deadlock_or_idle():
                    continue
                break

            tid = self._ready_queue.popleft()
            if tid not in self._tasks_map or tid in self._blocking_set:
                continue

            task = self._tasks_map[tid]
            self._pcb.current_tid = tid

            self._execute_task(task)
            self._handle_task_post_execution(task)
            self._cleanup_dead_tasks()