package sofixer

import "fmt"

// Elf64_Ehdr represents the main ELF header structure (e_ident + rest of header).
type Elf64_Ehdr struct {
	Magic      [4]byte // 0x00-0x03: Magic number
	Class      uint8   // 0x04: 32-bit or 64-bit
	Data       uint8   // 0x05: Little or big endian
	Version    uint8   // 0x06: ELF version
	OSABI      uint8   // 0x07: OS/ABI identification
	ABIVersion uint8   // 0x08: ABI version
	Padding    [7]byte // 0x09-0x0F: Unused
	Type       uint16  // 0x10-0x11: object file type
	Machine    uint16  // 0x12-0x13: architecture
	Version2   uint32  // 0x14-0x17: ELF version (again)
	Entry      uint64  // 0x18-0x1F: entry point virtual address
	PhdrOffset uint64  // 0x20-0x27: program header table file offset
	ShdrOffset uint64  // 0x28-0x2F: section header table file offset
	Flags      uint32  // 0x30-0x33: processor specific flags
	Ehsize     uint16  // 0x34-0x35: ELF header size
	Phentsize  uint16  // 0x36-0x37: size of an entry in the program header table
	Phnum      uint16  // 0x38-0x39: number of entries in the program header table
	Shentsize  uint16  // 0x3A-0x3B: size of an entry in the section header table
	Shnum      uint16  // 0x3C-0x3D: number of entries in the section header table
	Shstrndx   uint16  // 0x3E-0x3F: section header string table index
}

// Elf64_Phdr represents a 64-bit program header entry (Elf64_Phdr).
type Elf64_Phdr struct {
	Type   PT_Type // Segment type
	Flags  uint32  // Segment flags
	Offset uint64  // Segment file offset
	Vaddr  uint64  // Segment virtual address
	Paddr  uint64  // Segment physical address
	Filesz uint64  // Segment file size
	Memsz  uint64  // Segment memory size
	Align  uint64  // Segment alignment
}

// Elf64_Shdr represents a 64-bit section header entry (Elf64_Shdr).
type Elf64_Shdr struct {
	Name      uint32   // Section name (index into string table)
	Type      SHT_Type // Section type
	Flags     uint64   // Section flags
	Addr      uint64   // Address in memory
	Offset    uint64   // Offset in file
	Size      uint64   // Size of section in file
	Link      uint32   // Link to another section
	Info      uint32   // Additional section information
	Addralign uint64   // Section alignment
	Entsize   uint64   // Size of entries in section
}

// Elf64_Dyn represents a 64-bit dynamic section entry (Elf64_Dyn).
type Elf64_Dyn struct {
	Tag DT_Tag // Dynamic entry type
	Val uint64 // Value or pointer
}

// Elf64_Rela represents a 64-bit relocation entry with explicit addend (Elf64_Rela).
type Elf64_Rela struct {
	Offset uint64 // Address of reference
	Info   uint64 // Symbol index and type of relocation
	Addend int64  // Constant addend
}

// Elf64_Rel represents a 64-bit relocation entry without addend (Elf64_Rel).
type Elf64_Rel struct {
	Offset uint64 // Address of reference
	Info   uint64 // Symbol index and type of relocation
}

// Elf64_Sym represents a 64-bit ELF symbol table entry
type Elf64_Sym struct {
	St_Name  uint32 // Symbol name (index into string table)
	St_Info  uint8  // Symbol type and binding attributes
	St_Other uint8  // Visibility and other attributes
	St_Shndx uint16 // Section index where the symbol is defined
	St_Value uint64 // Value of the symbol (address or offset)
	St_Size  uint64 // Size of the symbol
}

type PT_Type uint32

const (
	PT_LOAD         PT_Type = 1
	PT_DYNAMIC      PT_Type = 2
	PT_INTERP       PT_Type = 3
	PT_NOTE         PT_Type = 4
	PT_PHDR         PT_Type = 6
	PT_TLS          PT_Type = 7
	PT_GNU_EH_FRAME PT_Type = 0x6474e550
	PT_GNU_STACK    PT_Type = 0x6474e551
	PT_GNU_RELRO    PT_Type = 0x6474e552
)

const (
	PF_X = 1 // Execute
	PF_W = 2 // Write
	PF_R = 4 // Read
)

func (sym Elf64_Sym) IsEmptySymbol() bool {
	return sym.St_Name == 0 && sym.St_Value == 0 && sym.St_Size == 0
}

type SHT_Type uint32

const (
	SHT_NULL        SHT_Type = 0
	SHT_PROGBITS    SHT_Type = 1
	SHT_SYMTAB      SHT_Type = 2
	SHT_STRTAB      SHT_Type = 3
	SHT_RELA        SHT_Type = 4
	SHT_HASH        SHT_Type = 5
	SHT_DYNAMIC     SHT_Type = 6
	SHT_NOTE        SHT_Type = 7
	SHT_NOBITS      SHT_Type = 8
	SHT_REL         SHT_Type = 9
	SHT_DYNSYM      SHT_Type = 11
	SHT_INIT_ARRAY  SHT_Type = 14
	SHT_FINI_ARRAY  SHT_Type = 15
	SHT_GNU_HASH    SHT_Type = 0x6ffffff6
	SHT_GNU_VERNEED SHT_Type = 0x6ffffffe
	SHT_GNU_VERSYM  SHT_Type = 0x6fffffff
)

type DT_Tag uint64

const (
	DT_NULL            DT_Tag = 0
	DT_NEEDED          DT_Tag = 1
	DT_PLTRELSZ        DT_Tag = 2
	DT_PLTGOT          DT_Tag = 3
	DT_HASH            DT_Tag = 4
	DT_STRTAB          DT_Tag = 5
	DT_SYMTAB          DT_Tag = 6
	DT_RELA            DT_Tag = 7
	DT_RELASZ          DT_Tag = 8
	DT_RELAENT         DT_Tag = 9
	DT_STRSZ           DT_Tag = 10
	DT_SYMENT          DT_Tag = 11
	DT_INIT            DT_Tag = 12
	DT_FINIT           DT_Tag = 13
	DT_SONAME          DT_Tag = 14
	DT_RPATH           DT_Tag = 15
	DT_SYMBOLIC        DT_Tag = 16
	DT_REL             DT_Tag = 17
	DT_RELSZ           DT_Tag = 18
	DT_RELENT          DT_Tag = 19
	DT_PLTREL          DT_Tag = 20
	DT_JMPREL          DT_Tag = 23
	DT_PREINIT_ARRAY   DT_Tag = 32
	DT_PREINIT_ARRAYSZ DT_Tag = 33
	DT_INIT_ARRAY      DT_Tag = 25
	DT_FINI_ARRAY      DT_Tag = 26
	DT_INIT_ARRAYSZ    DT_Tag = 27
	DT_FINI_ARRAYSZ    DT_Tag = 28
	DT_RUNPATH         DT_Tag = 29
	DT_FLAGS           DT_Tag = 30
	DT_GNU_HASH        DT_Tag = 0x6ffffef5
	DT_VERSYM          DT_Tag = 0x6ffffff0
	DT_RELACOUNT       DT_Tag = 0x6ffffff9
	DT_RELCOUNT        DT_Tag = 0x6ffffffa
	DT_FLAGS_1         DT_Tag = 0x6ffffffb
	DT_VERNEED         DT_Tag = 0x6ffffffe
	DT_VERNEEDNUM      DT_Tag = 0x6fffffff
)

// Elf64_Verneed represents GNU symbol version requirements
type Elf64_Verneed struct {
	Version uint16
	Cnt     uint16
	File    uint32
	Aux     uint32
	Next    uint32
}

// Elf64_Vernaux represents auxiliary information for version requirements
type Elf64_Vernaux struct {
	Hash  uint32
	Flags uint16
	Other uint16
	Name  uint32
	Next  uint32
}

// Elf64_Verdef represents GNU symbol version definitions
type Elf64_Verdef struct {
	Version uint16
	Flags   uint16
	Nd      uint16
	Cnt     uint16
	Hash    uint32
	Aux     uint32
	Next    uint32
}

// Elf64_Verdaux represents auxiliary information for version definitions
type Elf64_Verdaux struct {
	Name uint32
	Next uint32
}

func (p PT_Type) Text() string {
	switch p {
	case PT_LOAD:
		return "PT_LOAD"
	case PT_DYNAMIC:
		return "PT_DYNAMIC"
	case PT_INTERP:
		return "PT_INTERP"
	case PT_NOTE:
		return "PT_NOTE"
	case PT_PHDR:
		return "PT_PHDR"
	case PT_TLS:
		return "PT_TLS"
	case PT_GNU_EH_FRAME:
		return "PT_GNU_EH_FRAME"
	case PT_GNU_STACK:
		return "PT_GNU_STACK"
	case PT_GNU_RELRO:
		return "PT_GNU_RELRO"
	default:
		// Handle unknown or vendor-specific types
		return fmt.Sprintf("UNKNOWN_PT_TYPE(0x%x)", p)
	}
}

func (t SHT_Type) Text() string {
	switch t {
	case SHT_NULL:
		return "SHT_NULL"
	case SHT_PROGBITS:
		return "SHT_PROGBITS"
	case SHT_SYMTAB:
		return "SHT_SYMTAB"
	case SHT_STRTAB:
		return "SHT_STRTAB"
	case SHT_RELA:
		return "SHT_RELA"
	case SHT_HASH:
		return "SHT_HASH"
	case SHT_DYNAMIC:
		return "SHT_DYNAMIC"
	case SHT_NOTE:
		return "SHT_NOTE"
	case SHT_NOBITS:
		return "SHT_NOBITS"
	case SHT_REL:
		return "SHT_REL"
	case SHT_DYNSYM:
		return "SHT_DYNSYM"
	case SHT_INIT_ARRAY:
		return "SHT_INIT_ARRAY"
	case SHT_FINI_ARRAY:
		return "SHT_FINI_ARRAY"
	case SHT_GNU_HASH:
		return "SHT_GNU_HASH"
	case SHT_GNU_VERNEED:
		return "SHT_GNU_VERNEED"
	case SHT_GNU_VERSYM:
		return "SHT_GNU_VERSYM"
	default:
		return fmt.Sprintf("SHT_UNKNOWN(0x%x)", uint32(t))
	}
}

func (t DT_Tag) Text() string {
	switch t {
	case DT_NULL:
		return "DT_NULL"
	case DT_NEEDED:
		return "DT_NEEDED"
	case DT_PLTRELSZ:
		return "DT_PLTRELSZ"
	case DT_PLTGOT:
		return "DT_PLTGOT"
	case DT_HASH:
		return "DT_HASH"
	case DT_STRTAB:
		return "DT_STRTAB"
	case DT_SYMTAB:
		return "DT_SYMTAB"
	case DT_RELA:
		return "DT_RELA"
	case DT_RELASZ:
		return "DT_RELASZ"
	case DT_RELAENT:
		return "DT_RELAENT"
	case DT_STRSZ:
		return "DT_STRSZ"
	case DT_SYMENT:
		return "DT_SYMENT"
	case DT_SONAME:
		return "DT_SONAME"
	case DT_PLTREL:
		return "DT_PLTREL"
	case DT_JMPREL:
		return "DT_JMPREL"
	case DT_INIT_ARRAY:
		return "DT_INIT_ARRAY"
	case DT_FINI_ARRAY:
		return "DT_FINI_ARRAY"
	case DT_INIT_ARRAYSZ:
		return "DT_INIT_ARRAYSZ"
	case DT_FINI_ARRAYSZ:
		return "DT_FINI_ARRAYSZ"
	case DT_FLAGS:
		return "DT_FLAGS"
	case DT_GNU_HASH:
		return "DT_GNU_HASH"
	case DT_VERSYM:
		return "DT_VERSYM"
	case DT_FLAGS_1:
		return "DT_FLAGS_1"
	case DT_VERNEED:
		return "DT_VERNEED"
	case DT_VERNEEDNUM:
		return "DT_VERNEEDNUM"
	case DT_RELACOUNT:
		return "DT_RELACOUNT"
	case DT_RELCOUNT:
		return "DT_RELCOUNT"
	case DT_SYMBOLIC:
		return "DT_SYMBOLIC"
	case DT_PREINIT_ARRAY:
		return "DT_PREINIT_ARRAY"
	case DT_PREINIT_ARRAYSZ:
		return "DT_PREINIT_ARRAYSZ"
	default:
		return fmt.Sprintf("DT_UNKNOWN(0x%x)", t)
	}
}

type RelocationType uint32

const (
	R_AARCH64_NONE   RelocationType = 0x0   // 0
	R_AARCH64_ABS64  RelocationType = 0x101 // 257 (Direct 64-bit reference)
	R_AARCH64_ABS32  RelocationType = 0x102 // 258
	R_AARCH64_ABS16  RelocationType = 0x103 // 259
	R_AARCH64_PREL64 RelocationType = 0x104 // 260 (PC-relative 64-bit reference)
	R_AARCH64_PREL32 RelocationType = 0x105 // 261
	R_AARCH64_PREL16 RelocationType = 0x106 // 262

	// Used for dynamic linker fixups
	R_AARCH64_COPY       RelocationType = 0x108 // 264
	R_AARCH64_GLOB_DAT   RelocationType = 0x401 // 1025 (1 + 1024)
	R_AARCH64_JUMP_SLOT  RelocationType = 0x402 // 1026 (2 + 1024)
	R_AARCH64_RELATIVE   RelocationType = 0x403 // 1027 (3 + 1024)
	R_AARCH64_TLS_DTPMOD RelocationType = 0x404 // 1028
	R_AARCH64_TLS_DTPREL RelocationType = 0x405 // 1029

	// Other commonly used code-related relocations
	R_AARCH64_ADR_PREL21      RelocationType = 0x113 // 275
	R_AARCH64_ADD_ABS_LO12_NC RelocationType = 0x114 // 276
	R_AARCH64_CALL26          RelocationType = 0x11B // 283
	R_AARCH64_JUMP26          RelocationType = 0x11C // 284
)

func (r RelocationType) Text() string {
	switch r {
	case R_AARCH64_NONE:
		return "R_AARCH64_NONE"
	case R_AARCH64_ABS64:
		return "R_AARCH64_ABS64"
	case R_AARCH64_ABS32:
		return "R_AARCH64_ABS32"
	case R_AARCH64_ABS16:
		return "R_AARCH64_ABS16"
	case R_AARCH64_PREL64:
		return "R_AARCH64_PREL64"
	case R_AARCH64_PREL32:
		return "R_AARCH64_PREL32"
	case R_AARCH64_PREL16:
		return "R_AARCH64_PREL16"
	case R_AARCH64_COPY:
		return "R_AARCH64_COPY"
	case R_AARCH64_ADR_PREL21:
		return "R_AARCH64_ADR_PREL21"
	case R_AARCH64_ADD_ABS_LO12_NC:
		return "R_AARCH64_ADD_ABS_LO12_NC"
	case R_AARCH64_CALL26:
		return "R_AARCH64_CALL26"
	case R_AARCH64_JUMP26:
		return "R_AARCH64_JUMP26"
	case R_AARCH64_GLOB_DAT:
		return "R_AARCH64_GLOB_DAT"
	case R_AARCH64_JUMP_SLOT:
		return "R_AARCH64_JUMP_SLOT"
	case R_AARCH64_RELATIVE:
		return "R_AARCH64_RELATIVE"
	case R_AARCH64_TLS_DTPMOD:
		return "R_AARCH64_TLS_DTPMOD"
	case R_AARCH64_TLS_DTPREL:
		return "R_AARCH64_TLS_DTPREL"
	default:
		// Default case for unknown relocation types
		return fmt.Sprintf("UNKNOWN_RELOC_TYPE(%d)", r)
	}
}

type SymbolBinding uint8

const (
	STB_LOCAL  SymbolBinding = 0
	STB_GLOBAL SymbolBinding = 1
	STB_WEAK   SymbolBinding = 2
)

func (b SymbolBinding) Text() string {
	switch b {
	case STB_LOCAL:
		return "STB_LOCAL"
	case STB_GLOBAL:
		return "STB_GLOBAL"
	case STB_WEAK:
		return "STB_WEAK"
	default:
		// Default case for unknown symbol binding
		return fmt.Sprintf("STB_UNKNOWN_BINDING(%d)", b)
	}
}

type SymbolType uint8

const (
	STT_NOTYPE  SymbolType = 0
	STT_OBJECT  SymbolType = 1
	STT_FUNC    SymbolType = 2
	STT_SECTION SymbolType = 3
	STT_FILE    SymbolType = 4
	STT_COMMON  SymbolType = 5
	STT_TLS     SymbolType = 6
)

// Helper functions for symbol info
func (s Elf64_Sym) stBind() SymbolBinding {
	return SymbolBinding(s.St_Info >> 4)
}

func (s Elf64_Sym) stType() SymbolType {
	return SymbolType(s.St_Info & 0xf)
}

func (s Elf64_Sym) stInfo() uint8 {
	return (uint8(s.stBind()) << 4) | (uint8(s.stType()) & 0xf)
}

func (r Elf64_Rel) Type() RelocationType {
	return RelocationType(r.Info & 0xffffffff)
}

func (r Elf64_Rel) Sym() uint32 {
	return uint32(r.Info >> 32)
}

func (r Elf64_Rela) Type() RelocationType {
	return RelocationType(r.Info & 0xffffffff)
}

func (r Elf64_Rela) Sym() uint32 {
	return uint32(r.Info >> 32)
}

func PageStart(addr uint64) uint64 {
	mask := ^(0x1000 - 1)
	return addr & uint64(mask)
}

// AddrRange represents a range of virtual addresses occupied by a section
type AddrRange struct {
	Start uint64
	End   uint64
	Name  string
}

// ComputedSection holds metadata for sections discovered during analysis
type ComputedSection struct {
	Name      string
	Type      SHT_Type
	Flags     uint64
	Addr      uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}
