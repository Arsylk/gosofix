package sofixer

import (
	"fmt"

	"github.com/ianlancetaylor/demangle"
)

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
	Type   PT_Type  // Segment type
	Flags  PF_Flags // Segment flags
	Offset uint64   // Segment file offset
	Vaddr  uint64   // Segment virtual address
	Paddr  uint64   // Segment physical address
	Filesz uint64   // Segment file size
	Memsz  uint64   // Segment memory size
	Align  uint64   // Segment alignment
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

const (
	ELFCLASS64 = 2

	ET_DYN     = 3
	EM_AARCH64 = 183

	SHF_WRITE     = 0x1
	SHF_ALLOC     = 0x2
	SHF_EXECINSTR = 0x4
	SHF_INFO_LINK = 0x40

	// On-disk sizes of the ELF64 structures we read/write.
	sizeofEhdr    = 64
	sizeofPhdr    = 56
	sizeofShdr    = 64
	sizeofDyn     = 16
	sizeofSym     = 24
	sizeofRel     = 16
	sizeofRela    = 24
	sizeofVerneed = 16 // GNU version-need entry
	sizeofVernaux = 16 // GNU version-need auxiliary entry
	sizeofHashHdr = 8  // Nbucket + Nchain
	sizeofGNUHash = 16 // Nbuckets + Symndx + Maskwords + Shift2
)

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

type PF_Flags uint32

const (
	PF_X PF_Flags = 1 // Execute
	PF_W PF_Flags = 2 // Write
	PF_R PF_Flags = 4 // Read
)

func (f PF_Flags) Text() string {
	var s string
	if (f & PF_R) != 0 {
		s += "PF_R"
	}
	if (f & PF_W) != 0 {
		if s != "" {
			s += "|"
		}
		s += "PF_W"
	}
	if (f & PF_X) != 0 {
		if s != "" {
			s += "|"
		}
		s += "PF_X"
	}
	if s == "" {
		return "0"
	}
	return s
}

type SHT_Type uint32

const (
	SHT_NULL          SHT_Type = 0
	SHT_PROGBITS      SHT_Type = 1
	SHT_SYMTAB        SHT_Type = 2
	SHT_STRTAB        SHT_Type = 3
	SHT_RELA          SHT_Type = 4
	SHT_HASH          SHT_Type = 5
	SHT_DYNAMIC       SHT_Type = 6
	SHT_NOTE          SHT_Type = 7
	SHT_NOBITS        SHT_Type = 8
	SHT_REL           SHT_Type = 9
	SHT_DYNSYM        SHT_Type = 11
	SHT_INIT_ARRAY    SHT_Type = 14
	SHT_FINI_ARRAY    SHT_Type = 15
	SHT_PREINIT_ARRAY SHT_Type = 16
	SHT_GNU_HASH      SHT_Type = 0x6ffffff6
	SHT_GNU_VERNEED   SHT_Type = 0x6ffffffe
	SHT_GNU_VERSYM    SHT_Type = 0x6fffffff
	SHT_ANDROID_RELA  SHT_Type = 0x60000001
	SHT_ANDROID_REL   SHT_Type = 0x60000002
	SHT_RELR          SHT_Type = 19 // generic ABI; some toolchains also accept 0x6fffff00
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
	DT_FINI            DT_Tag = 13
	DT_SONAME          DT_Tag = 14
	DT_RPATH           DT_Tag = 15 // older spelling of DT_RUNPATH; handled equivalently
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
	DT_ANDROID_REL     DT_Tag = 0x6000000f
	DT_ANDROID_RELSZ   DT_Tag = 0x60000010
	DT_ANDROID_RELA    DT_Tag = 0x60000011
	DT_ANDROID_RELASZ  DT_Tag = 0x60000012
	DT_RELR            DT_Tag = 0x6fffff00
	DT_RELRSZ          DT_Tag = 0x6fffff01
	DT_RELRENT         DT_Tag = 0x6fffff03
	DT_RELRCOUNT       DT_Tag = 0x6fffff05
)

// Elf64_Verneed represents GNU symbol version requirements. We walk the chain
// in calculateVerneedSize but don't parse the Vernaux entries — only Verneed
// is needed to compute the section size.
type Elf64_Verneed struct {
	Version uint16
	Cnt     uint16
	File    uint32
	Aux     uint32
	Next    uint32
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
	case SHT_PREINIT_ARRAY:
		return "SHT_PREINIT_ARRAY"
	case SHT_GNU_HASH:
		return "SHT_GNU_HASH"
	case SHT_GNU_VERNEED:
		return "SHT_GNU_VERNEED"
	case SHT_GNU_VERSYM:
		return "SHT_GNU_VERSYM"
	case SHT_ANDROID_RELA:
		return "SHT_ANDROID_RELA"
	case SHT_ANDROID_REL:
		return "SHT_ANDROID_REL"
	case SHT_RELR:
		return "SHT_RELR"
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
	case DT_INIT:
		return "DT_INIT"
	case DT_FINI:
		return "DT_FINI"
	case DT_SONAME:
		return "DT_SONAME"
	case DT_RPATH:
		return "DT_RPATH"
	case DT_RUNPATH:
		return "DT_RUNPATH"
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
	case DT_ANDROID_REL:
		return "DT_ANDROID_REL"
	case DT_ANDROID_RELSZ:
		return "DT_ANDROID_RELSZ"
	case DT_ANDROID_RELA:
		return "DT_ANDROID_RELA"
	case DT_ANDROID_RELASZ:
		return "DT_ANDROID_RELASZ"
	case DT_RELR:
		return "DT_RELR"
	case DT_RELRSZ:
		return "DT_RELRSZ"
	case DT_RELRENT:
		return "DT_RELRENT"
	case DT_RELRCOUNT:
		return "DT_RELRCOUNT"
	default:
		return fmt.Sprintf("DT_UNKNOWN(0x%x)", t)
	}
}

type RelocationType uint32

const (
	R_AARCH64_NONE   RelocationType = 0x0   // 0
	R_AARCH64_ABS64  RelocationType = 0x101 // 257 (Direct 64-bit reference)
	R_AARCH64_PREL64 RelocationType = 0x104 // 260 (PC-relative 64-bit reference)

	// Used for dynamic linker fixups (ARM IHI 0056F §4.6.6)
	R_AARCH64_COPY       RelocationType = 0x400 // 1024
	R_AARCH64_GLOB_DAT   RelocationType = 0x401 // 1025
	R_AARCH64_JUMP_SLOT  RelocationType = 0x402 // 1026
	R_AARCH64_RELATIVE   RelocationType = 0x403 // 1027
	R_AARCH64_TLS_DTPMOD RelocationType = 0x404 // 1028
	R_AARCH64_TLS_DTPREL RelocationType = 0x405 // 1029
	R_AARCH64_TLS_TPREL  RelocationType = 0x406 // 1030
	R_AARCH64_TLSDESC    RelocationType = 0x407 // 1031
	R_AARCH64_IRELATIVE  RelocationType = 0x408 // 1032

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
	case R_AARCH64_PREL64:
		return "R_AARCH64_PREL64"
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
	case R_AARCH64_TLS_TPREL:
		return "R_AARCH64_TLS_TPREL"
	case R_AARCH64_TLSDESC:
		return "R_AARCH64_TLSDESC"
	case R_AARCH64_IRELATIVE:
		return "R_AARCH64_IRELATIVE"
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

func (t SymbolType) Text() string {
	switch t {
	case STT_NOTYPE:
		return "STT_NOTYPE"
	case STT_OBJECT:
		return "STT_OBJECT"
	case STT_FUNC:
		return "STT_FUNC"
	case STT_SECTION:
		return "STT_SECTION"
	case STT_FILE:
		return "STT_FILE"
	case STT_COMMON:
		return "STT_COMMON"
	case STT_TLS:
		return "STT_TLS"
	default:
		return fmt.Sprintf("STT_UNKNOWN(%d)", t)
	}
}

// Helper functions for symbol info
func (s Elf64_Sym) StBind() SymbolBinding {
	return SymbolBinding(s.St_Info >> 4)
}

func (s Elf64_Sym) StType() SymbolType {
	return SymbolType(s.St_Info & 0xf)
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

// HashHeader represents the initial part of the DT_HASH table.
type HashHeader struct {
	Nbucket uint32
	Nchain  uint32
}

// GNUHashHeader represents the initial part of the DT_GNU_HASH table.
type GNUHashHeader struct {
	Nbuckets  uint32
	Symndx    uint32
	Maskwords uint32
	Shift2    uint32
}

// AlignUp rounds up 'value' to the next multiple of 'align'
func AlignUp(value, align uint64) uint64 {
	if align == 0 {
		return value
	}
	return (value + align - 1) & ^(align - 1)
}

// DemangleSymbol attempts to demangle a C++ mangled symbol name.
// Returns the demangled name or the original if demangling fails.
func DemangleSymbol(name string) string {
	result, err := demangle.ToString(name)
	if err != nil {
		return name
	}
	return result
}
