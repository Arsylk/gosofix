# 🔧 gosofix

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux)](https://linux.org/)
[![Architecture](https://img.shields.io/badge/Target-ARM64%2FAArch64-red?style=flat)](https://en.wikipedia.org/wiki/AArch64)

**A tool to fix Android ARM64 shared object memory dumps for static analysis.**

gosofix processes memory-dumped `.so` files from Android processes and normalizes them back to valid ELF files that can be analyzed in tools like IDA Pro, Ghidra, or Binary Ninja.

## ✨ Features

- **Base address normalization** — Converts absolute virtual addresses back to relative offsets
- **Relocation processing** — Fixes `R_AARCH64_RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, and other relocation types
- **Section header reconstruction** — Rebuilds section headers from dynamic segment information
- **Symbol table fixing** — Normalizes symbol values and section indices
- **Init/Fini array patching** — Corrects constructor/destructor function pointers
- **Dual interface** — Available as CLI binary and shared library (for integration via `dlopen`)

## 📦 Installation

### Prerequisites

- [Go 1.25+](https://go.dev/dl/)
- [xmake](https://xmake.io/) (build system)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Arsylk/gosofix.git
cd gosofix

# Build CLI binary
xmake build gosofix

# Build shared library (optional)
xmake build libgosofix
```

Built artifacts are placed in the `dist/` directory:
- `dist/gosofix` — CLI executable
- `dist/libgosofix.so` — Shared library

## 🚀 Usage

### CLI

```bash
# Basic usage (auto-detect base address from filename)
./gosofix libexample.so_dump_0x7abc123000.so

# Explicit base address
./gosofix -i input.so -m 0x7abc123000 -o output_fixed.so

# With verbose output
./gosofix -v 2 -i input.so -m 0x7abc123000
```

### Command-Line Options

| Flag | Description |
|------|-------------|
| `-i` | Input file path |
| `-m` | Memory base address (hex) |
| `-o` | Output file path (default: `<input>_fix.so`) |
| `-v` | Verbosity level: `0`=quiet, `1`=info, `2`=debug |
| `--version` | Show version |

### Positional Arguments

```bash
# Equivalent forms:
./gosofix dump.so 0x7abc123000 output.so
./gosofix -i dump.so -m 0x7abc123000 -o output.so
```

### Library Usage

The shared library exports a `FixElf` function for integration:

```c
// C/C++ example
void* lib = dlopen("./libgosofix.so", RTLD_NOW);
typedef char* (*FixElfFunc)(const char*, uint64_t, const char*);
FixElfFunc fix = (FixElfFunc)dlsym(lib, "FixElf");

char* result = fix("/path/to/dump.so", 0x7abc123000, "/path/to/output.so");
// result contains success message or "error: ..."
free(result);
```

## 📖 How It Works

When a shared library is loaded into an Android process, the dynamic linker:
1. Maps the file at a runtime base address
2. Applies relocations (fixing up pointers with the base address)
3. Runs initializers

Memory dumps capture the **post-relocation** state. gosofix reverses this:

```
┌─────────────────────────────────────────────────────────────────┐
│  Memory Dump (absolute addresses)                               │
│  ┌──────────────────────────────────────────────────────┐      │
│  │ Entry: 0x7abc125000  (base + 0x2000)                 │      │
│  │ GOT[0]: 0x7abc130000 (base + actual_offset)          │      │
│  │ init_array[0]: 0x7abc12f000                          │      │
│  └──────────────────────────────────────────────────────┘      │
│                           │                                     │
│                           ▼  gosofix (subtract base 0x7abc123000)│
│  ┌──────────────────────────────────────────────────────┐      │
│  │ Entry: 0x2000                                        │      │
│  │ GOT[0]: 0xd000                                       │      │
│  │ init_array[0]: 0xc000                                │      │
│  └──────────────────────────────────────────────────────┘      │
│  Fixed ELF (relative offsets)                                   │
└─────────────────────────────────────────────────────────────────┘
```

### What Gets Fixed

| Component | Transformation |
|-----------|---------------|
| ELF Header (`e_entry`) | Normalize entry point |
| Program Headers (`p_vaddr`, `p_paddr`) | Normalize virtual addresses |
| Dynamic Section | Normalize address tags (`DT_STRTAB`, `DT_SYMTAB`, etc.) |
| Symbol Table (`st_value`) | Normalize symbol addresses |
| Relocations | Apply inverse relocation for target locations |
| Init/Fini Arrays | Normalize function pointers |
| Section Headers | Reconstruct from dynamic information |

## ⚠️ Limitations

- **ARM64/AArch64 only** — No support for x86, ARM32, or other architectures
- **Shared objects only** — Designed for `ET_DYN` (`.so`) files, not executables
- **Android memory dumps** — Assumes addresses contain the runtime base address

## 🔬 Testing

```bash
# Run full test suite
xmake test

# Or use the bulk test script
./run_all_tests.sh
```

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [charmbracelet/log](https://github.com/charmbracelet/log) — Styled logging
- [ianlancetaylor/demangle](https://github.com/ianlancetaylor/demangle) — C++ symbol demangling
