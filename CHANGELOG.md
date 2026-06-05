# Changelog 2026.06.05

## Fixed:

* `read_args` now read 8 registers for arm64 and 4 for arm32.
* Removed `ptr_sz` as arg for `read_ptr_sz` from `sigaction` syscall

## Changed:
* TLS now doesn't have abstract classes. Only one
* Add Canary Slot for arm64