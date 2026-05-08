Androcorn is a android native library emulation for ARM libraries by Unicorn Translation Layer.
It's builed as isolated framework for library. What does it's mean? All processes here trying to be kernel-free (actually, not clear, syscalls read/write/close and others are still a layer to your system.), so this mean you can run this project simillary on Windows and Linux!

I implemented in this framework more backward supports for libraries, like fork, execve, symlink and others. Also, if you read readme, new feature in the II generation of AndroCorn is a ASM code (like shell-code) exectuion. That's mean you can write your own scripts on asm and just map it to 0x1000 address. About Memory Mapping and other you will find out in this doc.

Other functionallity is basic: JNI Layer (not full implement), Java Layer (Java Types and Java Android Classes like android/net/wifi/WifiInfo and others, and yes not full implement!!!), Hooks (symbol hooks, address hooks aka function hooks), Interrupt handlers, Linker, Relocations, and other functional.

Project was tested on libc, C++ shared, libstdc++, and TikTok libraries (metasec, cms), and bugs... like im not found lol.

AndroCorn is still a beta-test project, what's mean it's not stable. Here is still rolling release that can broke some functionallity. But im trying to not break compability with ExAndroidNativeEmu (my thanks to maiyao1988, this project was really helpful when i started writing a emulator! ❤️)

::: androidemu.emulator.Emulator
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.scheduler.Scheduler
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.pcb.Pcb
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.utils.hooker.Hooker
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.internal.linker.AndroidLinker
    options:
      filters: ["!^_"]
      show_root_heading: true

::: androidemu.internal.module.Module
    options:
      filters: ["!^_"]
      show_root_heading: true