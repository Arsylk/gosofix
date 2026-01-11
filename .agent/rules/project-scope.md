---
trigger: always_on
glob:
description: Project scope and architecture constraints
---

# Project Constraints

This project (`sofixgo`) is specifically designed for:

1. **Architecture**: ARM64/AArch64 only - do NOT add support for other architectures (x86, ARM32, etc.)
2. **Target**: Android memory dumps of shared objects (.so files)
3. **ELF Class**: 64-bit ELF only (ELFCLASS64)

## Key Assumptions

- Input files are memory dumps from Android processes
- Virtual addresses in the dump are absolute (contain base address)
- Relocation entries have already been applied by the dynamic linker
- The goal is to normalize values back to relative offsets for static analysis

## Do NOT Implement

- 32-bit ELF support
- Non-ARM architectures
- Static ELF files (only shared objects)
- Relocation types not used on Android ARM64
