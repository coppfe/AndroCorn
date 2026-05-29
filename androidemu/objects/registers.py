from    unicorn.arm_const      import *
from    unicorn.arm64_const    import *


from    ..const                import emu_const

from    typing                 import List

class RegistersMapping:
    def __init__(self, arch: int) -> None:
        if arch == emu_const.ARCH_ARM32:
            self.any_0:         int             =         UC_ARM_REG_R0             # return (arg0)
            self.any_1:         int             =         UC_ARM_REG_R1             # any, (arg1)
            self.any_2:         int             =         UC_ARM_REG_R2             # any, (arg2)
            self.any_3:         int             =         UC_ARM_REG_R3             # any, (arg3)
            self.any_4:         int             =         UC_ARM_REG_R4             # any
            self.any_5:         int             =         UC_ARM_REG_R5             # any
            self.any_6:         int             =         UC_ARM_REG_R6             # any
            self.any_7:         int             =         UC_ARM_REG_R7             # any, syscall
            self.any_8:         int             =         UC_ARM_REG_R8             # any
            self.any_9:         int             =         UC_ARM_REG_R9             # any
            self.any_10:        int             =         UC_ARM_REG_R10            # any
            self.any_11:        int             =         UC_ARM_REG_R11            # any
            self.any_12:        int             =         UC_ARM_REG_R12            # any
            self.any_13:        int             =         UC_ARM_REG_R13            # any
            self.any_14:        int             =         UC_ARM_REG_R14            # any
            self.any_15:        int             =         UC_ARM_REG_R15            # any

            self.pc:            int             =         UC_ARM_REG_PC             # Program Counter
            self.sp:            int             =         UC_ARM_REG_SP             # Stack Pointer
            self.lr:            int             =         UC_ARM_REG_LR             # LR
            self.tls:           int             =         UC_ARM_REG_C13_C0_3       # C13_C0_3
            self.cpsr:          int             =         UC_ARM_REG_CPSR           # Current Program Status Register

            self.default:       List[int]       =         [
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                UC_ARM_REG_R12, UC_ARM_REG_LR
            ]

            self.arguments:     List[int]       =         [
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
            ]

            # aliases       

            self.ret:           int             =         self.any_0
            self.syscall:       int             =         self.any_7

        elif arch == emu_const.ARCH_ARM64:
            self.any_0:         int             =         UC_ARM64_REG_X0           # return (arg0)
            self.any_1:         int             =         UC_ARM64_REG_X1           # any, (arg1)
            self.any_2:         int             =         UC_ARM64_REG_X2           # any, (arg2)
            self.any_3:         int             =         UC_ARM64_REG_X3           # any, (arg3)
            self.any_4:         int             =         UC_ARM64_REG_X4           # any, (arg4)
            self.any_5:         int             =         UC_ARM64_REG_X5           # any, (arg5)
            self.any_6:         int             =         UC_ARM64_REG_X6           # any, (arg6)
            self.any_7:         int             =         UC_ARM64_REG_X7           # any, (arg7)
            self.any_8:         int             =         UC_ARM64_REG_X8           # any, syscall, (arg8)
            self.any_9:         int             =         UC_ARM64_REG_X9           # any
            self.any_10:        int             =         UC_ARM64_REG_X10          # any
            self.any_11:        int             =         UC_ARM64_REG_X11          # any
            self.any_12:        int             =         UC_ARM64_REG_X12          # any
            self.any_13:        int             =         UC_ARM64_REG_X13          # any
            self.any_14:        int             =         UC_ARM64_REG_X14          # any
            self.any_15:        int             =         UC_ARM64_REG_X15          # any
            self.any_16:        int             =         UC_ARM64_REG_X16          # any
            self.any_17:        int             =         UC_ARM64_REG_X17          # any
            self.any_18:        int             =         UC_ARM64_REG_X18          # any
            self.any_19:        int             =         UC_ARM64_REG_X19          # any
            self.any_20:        int             =         UC_ARM64_REG_X20          # any
            self.any_21:        int             =         UC_ARM64_REG_X21          # any
            self.any_22:        int             =         UC_ARM64_REG_X22          # any
            self.any_23:        int             =         UC_ARM64_REG_X23          # any
            self.any_24:        int             =         UC_ARM64_REG_X24          # any
            self.any_25:        int             =         UC_ARM64_REG_X25          # any
            self.any_26:        int             =         UC_ARM64_REG_X26          # any
            self.any_27:        int             =         UC_ARM64_REG_X27          # any
            self.any_28:        int             =         UC_ARM64_REG_X28          # any
            self.any_29:        int             =         UC_ARM64_REG_X29          # any
            self.any_30:        int             =         UC_ARM64_REG_X30          # LR

            self.pc:            int             =         UC_ARM64_REG_PC           # Program Counter
            self.sp:            int             =         UC_ARM64_REG_SP           # Stack Pointer
            self.lr:            int             =         UC_ARM64_REG_X30          # LR
            self.tls:           int             =         UC_ARM64_REG_TPIDR_EL0    # TPIDR_EL0
            self.nzcv:          int             =         UC_ARM64_REG_NZCV         # Negative, Zero, Carry, oVerflow (wtf)

            self.default:       List[int]           =         [
                UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,
                UC_ARM64_REG_X4,  UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,
                UC_ARM64_REG_X8,  UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11,
                UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
                UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
                UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
                UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
                UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30
            ]

            self.arguments:    List[int]        = [
                UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,
                UC_ARM64_REG_X4,  UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7
            ]

            # aliases

            self.ret:           int             =         self.any_0
            self.syscall:       int             =         self.any_8

        else:
            raise RuntimeError("Wrong arch identifier. Except '1' for ARM32 or '2' for ARM64")
    
    def __getattr__(self, name):
        return None