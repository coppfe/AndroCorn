# Register Mapping & Calling Convention (ABI)

AndroCorn v2.0 provides an intuitive virtual property API for reading and writing CPU registers across ARM32 and ARM64 architectures via `emu.registers`.

---

## Virtual Register Property API (`v_*`)

All CPU registers can be accessed as direct attributes with the `v_` prefix:

```python
regs = emu.registers

# Reading registers
pc = regs.v_pc
sp = regs.v_sp
lr = regs.v_lr
arg0 = regs.v_reg_0
arg1 = regs.v_reg_1
syscall_num = regs.v_syscall

# Writing registers
regs.v_reg_0 = 0x1337
regs.v_sp = 0x107FE000
regs.v_pc = 0x4001A200
regs.v_ret = 0
```

## Architecture-Agnostic Calling Convention

Reading and writing function arguments adheres to the target architecture ABI (AAPCS for ARM32, AAPCS64 for ARM64).

### 1. Writing Arguments

Arguments that do not fit into the architecture's register set are automatically packed and pushed onto the stack with 16-byte alignment:

```python
# Pass parameters to native functions
regs.write_args(emu.java_vm, 1, 2, "my_string", b"payload", 5, 6, 7, 8, 9)
```

### 2. Reading Function Arguments

```python
# Automatically reads register arguments and falls back to stack dereferencing
args = regs.read_args(count=8)
```

### 3. Thumb Mode Control (ARM32)

```python
if regs.is_thumb():
    print("CPU is currently in Thumb execution mode")

regs.set_thumb()    # Sets the T-bit (bit 5) in CPSR
regs.clear_thumb()  # Clears the T-bit in CPSR
```

