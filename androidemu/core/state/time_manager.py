import random
import time

class TimeManager:
    def __init__(self, start_timestamp=None):
        """
        Manages virtual system time and uptime. 
        Replaces real-world blocking delays with deterministic virtual time increments.
        Integrates with Scheduler and SyscallHandlers to provide instant 'sleep' 
        execution without hanging the host process.
        """
        now = int(time.time())
        self.virtual_us = (start_timestamp if start_timestamp else now) * 1000000
        self.uptime_us = random.randint(7200, 36000) * 1000000

    def advance_time(self, microseconds: int):
        self.virtual_us += microseconds
        self.uptime_us += microseconds

    def jump_to_time(self, target_us: int):
        diff = target_us - self.virtual_us
        if diff > 0:
            self.advance_time(diff)

    def get_timeofday(self):
        self.advance_time(random.randint(15, 45))
        sec = self.virtual_us // 1000000
        usec = self.virtual_us % 1000000
        return sec, usec

    def get_clock_monotonic(self):
        self.advance_time(random.randint(10, 30))
        sec = self.uptime_us // 1000000
        nsec = (self.uptime_us % 1000000) * 1000
        return sec, nsec
    
    def get_current_time_us(self) -> int:
        return self.virtual_us