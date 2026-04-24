# Changelog 2026.04.23

## Changed:
* readlinkat/unlinkat virtual implement (in test)
* code refactoring
* linux compabilty fixes.
* `prepare_path` was removed and now here is new 3 functions:
  - `is_virtual`
  - `generate`
  - `resolve_dir_entries` (for getdents64)
* `use_cache` for load_library
* linux errno consts