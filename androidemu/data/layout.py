PAGE_SIZE                       = 0x1000

ASM_CODE                        = 0x1000

BRIDGE_MEMORY_BASE              = 0x01000000
BRIDGE_MEMORY_SIZE              = 0x00200000                    # 2 MB
HOOK_STUB_BASE                  = 0x01200000
HOOK_STUB_MEMORY_SIZE           = 0x00100000                    # 1 MB

TLS_BASE                        = 0x02000000
TLS_SIZE                        = 0x00010000                    # 64 KB

STOP_MEMORY_BASE                = 0x03000000
STOP_MEMORY_SIZE                = 0x00002000                    # 8 KB
SIGRET                          = STOP_MEMORY_BASE + 0x1000

STACK_ADDR                      = 0x10000000                    
STACK_SIZE                      = 1024 * 1024 * 8               # 8 MB (0x10000000 - 0x10800000)
CHILD_STACK_ADDR                = 0x11000000                    

SOINFO_START_BASE               = 0x20000000
SOINFO_SIZE                     = 0x01000000                    # 16 MB

BASE_ADDR                       = 0x40000000                    

EMU_HEAP_BASE                   = 0x60000000
EMU_HEAP_SIZE                   = 0x08000000                    # 128 MB

BRK_BASE                        = 0x70000000
BRK_SIZE                        = 0x00800000                    # 8 MB

MMAP_BASE                       = 0x80000000
MMAP_SIZE                       = 0x20000000                    # 512 MB

APP_PROCESS_BASE                = 0xAB000000                    
LINKER_BASE                     = 0xB6F00000

JMETHOD_ID_BASE                 = 0xD2000000
JFIELD_ID_BASE                  = 0xE2000000

VECTORS_BASE                    = 0xFFFF0000

HIDE = [
    ASM_CODE,
    BRIDGE_MEMORY_BASE,
    HOOK_STUB_BASE,
    TLS_BASE,
    SOINFO_START_BASE,
    STOP_MEMORY_BASE,
    EMU_HEAP_BASE,
    JMETHOD_ID_BASE,
    JFIELD_ID_BASE
]