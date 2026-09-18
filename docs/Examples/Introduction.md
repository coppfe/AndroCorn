# Process Control Block & Runtime State

In AndroCorn v2.0, process and thread parameters are managed exclusively by the `ProcessControlBlock` (`emu.pcb`).

---

## Inspecting and Modifying Process Identity

```python
from androidemu import Emulator

emu = Emulator(vfs_root="vfs")

# Reading process metadata
print(f"PID:          {emu.pcb.pid}")
print(f"PPID:         {emu.pcb.ppid}")
print(f"UID:          {emu.pcb.uid}")
print(f"Process Name: {emu.pcb.process_name}")

# Modifying state at runtime
emu.pcb.process_name = "com.top.secret.app"
emu.pcb.dumpable = 1
emu.pcb.ptrace = 0  # Simulates untraced process state
```