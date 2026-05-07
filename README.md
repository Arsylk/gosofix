# 🔧 gosofix

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux)](https://linux.org/)
[![Architecture](https://img.shields.io/badge/Target-ARM64%2FAArch64-red?style=flat)](https://en.wikipedia.org/wiki/AArch64)

**A tool to fix Android ARM64 shared object memory dumps for static analysis.**

gosofix processes memory-dumped `.so` files from Android processes and normalizes them back to valid ELF files that can be analyzed in tools like IDA Pro, Ghidra, or Binary Ninja.

### Key Features

- **ELF 64-bit ARM64 Support**: Specialized for Android shared objects.
- **Robust Relocation Normalization**: Handles `ABS64`, `GLOB_DAT`, `JUMP_SLOT`, and `RELATIVE` relocations. Automatically detects and normalizes "dirty" addends in memory dumps (absolute pointers poisoned by runtime linkers).
- **Accurate PC-Relative Fixes**: Properly handles `R_AARCH64_PREL64` using virtual addresses.
- **APS2/APA1 & RELR Support**: Full support for Android packed relocations (SLEB128 and bitmap formats).
- **Preserved Runtime Data**: Reconstructs `.bss` as `PROGBITS` to preserve values initialized at runtime (e.g., by packers).
- **Intelligent Section Reconstruction**: Automatically identifies gaps between known structures and creates descriptive placeholder sections (`.text.gap_N`, `.data.gap_N`) to ensure full coverage in static analysis tools.
- **Post-Fix Verification**: Built-in sanity checker validates headers, segment consistency, and scans for residual absolute addresses.
- **Page Alignment Support**: Detects and maintains 4KB/16KB/64KB alignment found in dumped segments.
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
1. Maps the file at a runtime base address (ASLR)
2. Applies relocations (fixing up pointers with the base address)
3. Initializes `.bss` and runs constructors

Memory dumps capture the **post-relocation** state with live runtime data. gosofix reverses this:

```
┌─────────────────────────────────────────────────────────────────┐
│  Memory Dump (absolute addresses)                               │
│  ┌──────────────────────────────────────────────────────┐      │
│  │ Entry: 0x7abc125000  (base + 0x2000)                 │      │
│  │ GOT[0]: 0x7abc130000 (base + actual_offset)          │      │
│  │ .bss globals: live runtime values                    │      │
│  └──────────────────────────────────────────────────────┘      │
│                           │                                     │
│                           ▼  gosofix                            │
│  ┌──────────────────────────────────────────────────────┐      │
│  │ Entry: 0x2000                                        │      │
│  │ GOT[0]: 0xd000                                       │      │
│  │ .bss globals: preserved as SHT_PROGBITS              │      │
│  └──────────────────────────────────────────────────────┘      │
│  Fixed ELF (relative offsets, runtime data preserved)           │
└─────────────────────────────────────────────────────────────────┘
```

### What Gets Fixed

| Component | Transformation |
|-----------|---------------|
| ELF Header (`e_entry`) | Normalize entry point |
| Program Headers (`p_vaddr`, `p_paddr`) | Normalize virtual addresses |
| Dynamic Section | Normalize address tags (`DT_STRTAB`, `DT_SYMTAB`, etc.) |
| Symbol Table (`st_value`) | Normalize symbol addresses |
| Standard Relocations (RELA/REL) | Apply inverse relocation for target locations |
| Packed Relocations (APS2/APA1) | Decode SLEB128 stream, normalize targets |
| RELR Bitmap Relocations | Decode bitmap entries, normalize targets |
| Init/Fini Arrays | Normalize function pointers |
| `.bss` / Runtime Data | Preserved as-is (not zeroed) |
| Section Headers | Reconstructed from dynamic information |

## ⚠️ Limitations

- **ARM64/AArch64 only** — No support for x86, ARM32, or other architectures
- **Shared objects only** — Designed for `ET_DYN` (`.so`) files, not executables
- **Android memory dumps** — Assumes addresses contain the runtime base address

## 🔬 Testing

```bash
# Run full test suite (5 diverse samples + build verification)
xmake test
```

The test suite covers samples with varying characteristics:
- Different packers (Jiagu, DexProtector, custom)
- Varying sizes (252KB to 3MB)
- Different relocation configurations
- Corrupted/missing section headers in dumps

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [charmbracelet/log](https://github.com/charmbracelet/log) — Styled logging
- [ianlancetaylor/demangle](https://github.com/ianlancetaylor/demangle) — C++ symbol demangling
