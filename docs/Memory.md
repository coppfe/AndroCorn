# Memory

## Memory Constants

From androidemu/data/mem_map.py

| Name | Value | Notes |
| :--- | :--- | :--- |
| `ASM_CODE` | `0x1000` | - |
| `BRIDGE_MEMORY_BASE` | `0x01000000` | - |
| `BRIDGE_MEMORY_SIZE` | `0x00200000` | - |
| `HOOK_STUB_ADDRESS ` | `0x0` | It's anywhere |
| `HOOK_STUB_MEMORY_SIZE` | `0x00100000` | - |
| `TLS_BASE` | `0x02000000` | - |
| `TLS_SIZE` | `0x00010000` | - |
| `STACK_ADDR` | `0x10000000` | 8 MB stack |
| `STACK_SIZE` | `0x00800000` | computed |
| `CHILD_STACK_ADDR` | `0x90000000` | - |
| `SOINFO_START_BASE` | `0x20000000` | - |
| `SOINFO_SIZE` | `0x01000000` | - |
| `BASE_ADDR` | `0x40000000` | - |
| `STOP_MEMORY_BASE` | `0x03000000` | - |
| `STOP_MEMORY_SIZE` | `0x00001000` | - |
| `MAP_ALLOC_BASE` | `0x70000000` | - |
| `MAP_ALLOC_SIZE` | `0x50000000` | computed |
| `JMETHOD_ID_BASE` | `0xD2000000` | - |
| `JFIELD_ID_BASE` | `0xE2000000` | - |
| `VECTORS_BASE` | `0xFFFF0000` | - |
| `APP_PROCESS_BASE` | `0xAB006000` | - |
| `PAGE_SIZE` | `0x1000` | - |


### Memory Helpers
::: androidemu.utils.memory.memory_helpers
    options:
      filters: ["!^_"]
      show_root_heading: false
      show_root_toc_entry: false
      heading_level: 4
### Memory Mapper
::: androidemu.utils.memory.memory_map.MemoryMap
    options:
      filters: ["!^_"]
      show_root_heading: false
      show_root_toc_entry: false
      heading_level: 4

### Struct Writer
::: androidemu.utils.memory.struct_writer.StructWriter
    options:
      filters: ["!^_"]
      show_root_heading: false
      show_root_toc_entry: false
      heading_level: 4
