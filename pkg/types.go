package sofixer

import "fmt"


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

type DT_Tag uint64
const (
	DT_NULL         DT_Tag = 0
	DT_NEEDED       DT_Tag = 1
	DT_PLTRELSZ     DT_Tag = 2
	DT_PLTGOT       DT_Tag = 3
	DT_HASH         DT_Tag = 4
	DT_STRTAB       DT_Tag = 5
	DT_SYMTAB       DT_Tag = 6
	DT_RELA         DT_Tag = 7
	DT_RELASZ       DT_Tag = 8
	DT_RELAENT      DT_Tag = 9
	DT_STRSZ        DT_Tag = 10
	DT_SYMENT       DT_Tag = 11
	DT_SONAME       DT_Tag = 14
	DT_REL          DT_Tag = 17
	DT_RELSZ        DT_Tag = 18
	DT_RELENT       DT_Tag = 19
	DT_PLTREL       DT_Tag = 20
	DT_JMPREL       DT_Tag = 23
	DT_INIT_ARRAY   DT_Tag = 25
	DT_FINI_ARRAY   DT_Tag = 26
	DT_INIT_ARRAYSZ DT_Tag = 27
	DT_FINI_ARRAYSZ DT_Tag = 28
	DT_FLAGS        DT_Tag = 30
	DT_GNU_HASH     DT_Tag = 0x6ffffef5
	DT_VERSYM       DT_Tag = 0x6ffffff0
	DT_RELACOUNT    DT_Tag = 0x6ffffff9
	DT_RELCOUNT     DT_Tag = 0x6ffffffa
	DT_FLAGS_1      DT_Tag = 0x6ffffffb
	DT_VERNEED      DT_Tag = 0x6ffffffe
	DT_VERNEEDNUM   DT_Tag = 0x6fffffff
)

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
	default:
		return fmt.Sprintf("DT_UNKNOWN(%d)", t)
	}
}

type RelocationType uint32

const (
    R_AARCH64_NONE      RelocationType = 0   // No relocation
    R_AARCH64_ABS64     RelocationType = 257 // Direct 64-bit reference
    R_AARCH64_ABS32     RelocationType = 258 // Direct 32-bit reference
    R_AARCH64_ABS16     RelocationType = 259 // Direct 16-bit reference
    R_AARCH64_PREL64    RelocationType = 260 // PC-relative 64-bit reference
    R_AARCH64_PREL32    RelocationType = 261 // PC-relative 32-bit reference
    R_AARCH64_PREL16    RelocationType = 262 // PC-relative 16-bit reference

    // Used for dynamic linker fixups (as seen in your code)
    R_AARCH64_RELATIVE  RelocationType = 1027 // (3 + 1024) Adjust by (B + A)
    R_AARCH64_COPY      RelocationType = 264
    R_AARCH64_GLOB_DAT  RelocationType = 1025 // (1 + 1024) Set GOT entry to address of symbol
    R_AARCH64_JUMP_SLOT RelocationType = 1026 // (2 + 1024) Set PLT entry to address of symbol
    R_AARCH64_TLS_DTPMOD RelocationType = 1028 // Module ID
    R_AARCH64_TLS_DTPREL RelocationType = 1029 // Offset in TLS block

    // Other commonly used code-related relocations
    R_AARCH64_ADR_PREL21 RelocationType = 275
    R_AARCH64_ADD_ABS_LO12_NC RelocationType = 276
    R_AARCH64_CALL26    RelocationType = 283  // Function call (26-bit immediate)
    R_AARCH64_JUMP26    RelocationType = 284  // Function jump (26-bit immediate)
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
func (s SymbolEntry) stBind() SymbolBinding {
	return SymbolBinding(s.St_Info >> 4)
}

func (s SymbolEntry) stType() SymbolType {
	return SymbolType(s.St_Info & 0xf)
}

func (s SymbolEntry) stInfo() uint8 {
	return (uint8(s.stBind()) << 4) | (uint8(s.stType()) & 0xf)
}

func (r RelEntry) Type() RelocationType {
	return RelocationType(r.Info & 0xffffffff)
}

func (r RelEntry) Sym() uint32 {
	return uint32(r.Info >> 32)
}

func (r RelaEntry) Type() RelocationType {
	return RelocationType(r.Info & 0xffffffff)
}

func (r RelaEntry) Sym() uint32 {
	return uint32(r.Info >> 32)
}

func PageStart(addr uint64) uint64 {
	mask := ^(0x1000 - 1)
    return addr & uint64(mask)
}
