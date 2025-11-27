package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/fatih/color"
)

var (
	debugEnabled bool
	// Color functions for different elements (Base16 Catppuccin Mocha inspired)
	cPrefix  = color.New(color.FgHiCyan).SprintFunc()   // Mauve
	cText    = color.New(color.FgWhite).SprintFunc()    // Text
	cValue   = color.New(color.FgHiYellow).SprintFunc() // Green
	fValue   = func(value interface{}) string { return cAddress(fmt.Sprintf("%d", value)) }
	cAddress = color.New(color.FgHiBlue).SprintFunc() // Blue
	fAddress = func(addr uint64) string { return cAddress(fmt.Sprintf("0x%x", addr)) }
	cPath    = color.New(color.FgHiGreen).SprintFunc()              // Yellow
	cSuccess = color.New(color.FgHiYellow, color.Bold).SprintFunc() // Green Bold
	cWarning = color.New(color.FgHiRed, color.Bold).SprintFunc()    // Orange Bold
)

func logDebug(a ...interface{}) {
	if debugEnabled {
		fmt.Printf("%s %s\n", cPrefix("[D]"), fmt.Sprint(a...))
	}
}

func logInfo(a ...interface{}) {
	fmt.Printf("%s %s\n", cPrefix("[I]"), fmt.Sprint(a...))
}

type ElfReader struct {
	File *os.File
	ElfHeader *ELFHeader
	Phdrs []ProgramHeader
	Dyns []DynamicEntry
	Sections *[]SectionHeader
	Rel []RelEntry
	Rela []RelaEntry
	JmpRel []RelEntry
	JmpRela []RelaEntry
	Symbols []SymbolEntry

	dynMap map[DT_Tag]uint64
	strtabOffset uint64
	symtabOffset uint64
	relOffset uint64
	relSize uint64
	relaOffset uint64
	relaSize uint64
	jmprelOffset uint64
	jmprelSize  uint64
	jmprelEntry uint64
	phdrPtLoadPageStart uint64

	symCount uint64
}

const (
	ELFCLASS32 = 1
	ELFCLASS64 = 2

	ET_DYN          = 3
	EM_AARCH64      = 183

	// Section Header Types (SHT)
	SHT_NULL        = 0
	SHT_PROGBITS    = 1
	SHT_SYMTAB      = 2
	SHT_STRTAB      = 3
	SHT_RELA        = 4
	SHT_HASH        = 5
	SHT_DYNAMIC     = 6
	SHT_NOTE        = 7
	SHT_NOBITS      = 8
	SHT_REL         = 9
	SHT_DYNSYM      = 11
	SHT_INIT_ARRAY  = 14
	SHT_FINI_ARRAY  = 15
	SHT_GNU_HASH    = 0x6ffffff6
	SHT_GNU_VERNEED = 0x6ffffffe
	SHT_GNU_VERSYM  = 0x6fffffff

	// Section Header Flags (SHF)
	SHF_WRITE     = 0x1
	SHF_ALLOC     = 0x2
	SHF_EXECINSTR = 0x4
	SHF_INFO_LINK = 0x40
)

// DynamicEntry represents a 64-bit dynamic section entry (Elf64_Dyn).
type DynamicEntry struct {
	Tag DT_Tag // Dynamic entry type
	Val uint64 // Value or pointer
}

// RelaEntry represents a 64-bit relocation entry with explicit addend (Elf64_Rela).
type RelaEntry struct {
	Offset uint64 // Address of reference
	Info   uint64 // Symbol index and type of relocation
	Addend int64  // Constant addend
}

// RelEntry represents a 64-bit relocation entry without addend (Elf64_Rel).
type RelEntry struct {
	Offset uint64 // Address of reference
	Info   uint64 // Symbol index and type of relocation
}

// SectionHeader represents a 64-bit section header entry (Elf64_Shdr).
type SectionHeader struct {
	Name      uint32 // Section name (index into string table)
	Type      uint32 // Section type
	Flags     uint64 // Section flags
	Addr      uint64 // Address in memory
	Offset    uint64 // Offset in file
	Size      uint64 // Size of section in file
	Link      uint32 // Link to another section
	Info      uint32 // Additional section information
	Addralign uint64 // Section alignment
	Entsize   uint64 // Size of entries in section
}

// ELFHeader represents the main ELF header structure (e_ident + rest of header).
type ELFHeader struct {
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

// ProgramHeader represents a 64-bit program header entry (Elf64_Phdr).
type ProgramHeader struct {
	Type   PT_Type// Segment type
	Flags  uint32 // Segment flags
	Offset uint64 // Segment file offset
	Vaddr  uint64 // Segment virtual address
	Paddr  uint64 // Segment physical address
	Filesz uint64 // Segment file size
	Memsz  uint64 // Segment memory size
	Align  uint64 // Segment alignment
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

// SectionInfo is a helper struct to build the SHT.
type SectionInfo struct {
	Name      string
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

type SymbolEntry struct {
    St_Name  uint32 // Symbol name (index into string table)
    St_Info  uint8  // Symbol type and binding attributes
    St_Other uint8  // Visibility and other attributes
    St_Shndx uint16 // Section index where the symbol is defined
    St_Value uint64 // Value of the symbol (address or offset)
    St_Size  uint64 // Size of the symbol
}


// alignUp rounds up 'value' to the next multiple of 'align'
func alignUp(value, align uint64) uint64 {
	if align == 0 {
		return value
	}
	return (value + align - 1) & ^(align - 1)
}

// FixELFHeaders attempts to fix common issues with ELF headers.
func FixELFHeaders(filePath string, baseAddr uint64, debug bool) error {
	debugEnabled = debug
	logInfo(cText("Starting ELF fix for file: "), cPath(filePath), cText(" at base address "), fAddress(baseAddr))

	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var reader ElfReader = ElfReader{
		File: file,
		ElfHeader: new(ELFHeader),
	}

	// 1. Read and validate ELF header
	if err := reader.ReadElfHeaders(); err != nil {
		return err
	}

	// 2. Read Program Header Table (PHT)
	if err := reader.ReadPhdrs(); err != nil {
		return err
	}

	// 3. Read Dynamic Section (DT)
	if err := reader.ReadDyns(); err != nil {
		return err
	}

	// 4. Read Relocations (REL/RELA)
	if err := reader.ReadRelocs(); err != nil {
		return err
	}

	// 5. Fix Relocs
	if err := reader.FixRelocs(baseAddr); err != nil {
		return err
	}

	// // 3. Apply fixes to Program Headers
	// logInfo(cText("* Applying fixes to Program Headers..."))
	// if err := fixProgramHeaders(file, &header, phdrs, baseAddr); err != nil {
	// 	return fmt.Errorf("program header fix failed: %w", err)
	// }
	// logInfo(cSuccess("   -> Program Headers fixed successfully."))
	//
	// // 4. Fix Dynamic Section
	// logInfo(cText("* Fixing Dynamic Section..."))
	// if err := fixDynamicSection(file, phdrs, baseAddr); err != nil {
	// 	return fmt.Errorf("dynamic section fix failed: %w", err)
	// }
	// logInfo(cSuccess("   -> Dynamic Section fixed successfully."))
	//
	// // 5. Fix Relocations
	// logInfo(cText("* Fixing Relocations..."))
	// if err := fixRelocations(file, phdrs, baseAddr); err != nil {
	// 	return fmt.Errorf("relocation fix failed: %w", err)
	// }
	// logInfo(cSuccess("   -> Relocations fixed successfully."))
	//
	// // 6. Rebuild and Write Section Header Table
	// logInfo(cText("* Rebuilding and writing Section Header Table (SHT)..."))
	// if err := rebuildSectionHeaders(filePath, file, &header, phdrs, baseAddr); err != nil {
	// 	return fmt.Errorf("SHT rebuild failed: %w", err)
	// }
	// logInfo(cSuccess("   -> SHT rebuilt and written successfully."))
	//
	// // 7. Rewrite the fixed PHT back to the file
	// if _, err := file.Seek(int64(header.PhdrOffset), io.SeekStart); err != nil {
	// 	return fmt.Errorf("failed to seek to program header table for writing: %w", err)
	// }
	// if err := binary.Write(file, binary.LittleEndian, phdrs); err != nil {
	// 	return fmt.Errorf("failed to write fixed program header table: %w", err)
	// }
	//
	// // 8. Rewrite the fixed ELF header
	// if _, err := file.Seek(0, io.SeekStart); err != nil {
	// 	return fmt.Errorf("failed to seek to ELF header for writing: %w", err)
	// }
	// if err := binary.Write(file, binary.LittleEndian, &header); err != nil {
	// 	return fmt.Errorf("failed to write fixed ELF header: %w", err)
	// }

	return nil
}

func (r *ElfReader) ReadElfHeaders() error {
	logInfo(cText("* Reading and validating ELF header..."))
	if err := binary.Read(r.File, binary.LittleEndian, r.ElfHeader); err != nil {
		return fmt.Errorf("failed to read ELF header: %w", err)
	}
	if r.ElfHeader.Magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return fmt.Errorf("invalid ELF magic number: %x", r.ElfHeader.Magic)
	}
	if r.ElfHeader.Class != ELFCLASS64 {
		return fmt.Errorf("unsupported ELF class: %d (expected 64-bit)", r.ElfHeader.Class)
	}
	if r.ElfHeader.Phentsize != 56 {
		return fmt.Errorf("invalid program header entry size: %d (expected 56)", r.ElfHeader.Phentsize)
	}
	logInfo(cSuccess("   -> ELF header validated"), cText("(64-bit, Phentsize "), fValue(r.ElfHeader.Phentsize), cText(")"))

	return nil
}

func (r *ElfReader) ReadPhdrs() error {
	phtSize := uint64(r.ElfHeader.Phnum) * uint64(r.ElfHeader.Phentsize)
	if phtSize == 0 || r.ElfHeader.Phnum > 1024 {
		return fmt.Errorf("invalid number of program headers: %d", r.ElfHeader.Phnum)
	}
	logInfo(cText("* Reading PHT at offset "), fAddress(r.ElfHeader.PhdrOffset), cText(" e_phnum="), fValue(r.ElfHeader.Phnum))

	if _, err := r.File.Seek(int64(r.ElfHeader.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program header table: %w", err)
	}

	r.Phdrs = make([]ProgramHeader, r.ElfHeader.Phnum)
	if err := binary.Read(r.File, binary.LittleEndian, r.Phdrs); err != nil {
		return fmt.Errorf("failed to read program header table: %w", err)
	}

	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && r.phdrPtLoadPageStart == 0 {
			r.phdrPtLoadPageStart = PageStart(phdr.Vaddr)
		}
		logDebug(cText("  + "), cValue(phdr.Type.Text()), cText(" at "), fAddress(phdr.Offset), )
	}

	return nil
}

func (r *ElfReader) ReadDyns() error {
	var dynamicPhdr *ProgramHeader
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_DYNAMIC {
			dynamicPhdr = &phdr
			break
		}
	}

	logInfo(cText("* Reading DYN at offset "), fAddress(dynamicPhdr.Offset))
	if dynamicPhdr == nil {
		return nil
	}

	entryCount := dynamicPhdr.Memsz / 16

	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero size")
	}
	logDebug(cText("   -> Dynamic section found p_vaddr="), fAddress(dynamicPhdr.Vaddr), cText(", p_offset="), fAddress(dynamicPhdr.Offset), cText(", entries="), fValue(entryCount))

	// Read the dynamic section content
	r.Dyns = make([]DynamicEntry, entryCount)

	if _, err := r.File.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section: %w", err)
	}

	if err := binary.Read(r.File, binary.LittleEndian, r.Dyns); err != nil {
		return fmt.Errorf("failed to read dynamic section: %w", err)
	}


	r.dynMap = make(map[DT_Tag]uint64)
	for _, entry := range r.Dyns {
		logInfo(cText("    - dynamic "), cValue(entry.Tag.Text()), cText(" "), fValue(entry.Val))
		switch entry.Tag {
		case DT_STRTAB:
			r.strtabOffset = entry.Val
		case DT_SYMTAB:
			r.symtabOffset = entry.Val
		case DT_REL:
			r.relOffset = entry.Val
		case DT_RELSZ:
			r.relSize = entry.Val
		case DT_RELA:
			r.relaOffset = entry.Val
		case DT_RELASZ:
			r.relaSize = entry.Val
		case DT_JMPREL:
			r.jmprelOffset = entry.Val
		case DT_PLTREL:
			if entry.Val == uint64(DT_REL) {
				r.jmprelEntry = uint64(binary.Size(RelEntry{}))
			} else {
				r.jmprelEntry = uint64(binary.Size(RelaEntry{}))
			}
		case DT_PLTRELSZ:
			r.jmprelSize = entry.Val
		}
		r.dynMap[entry.Tag] = entry.Val
	}

	return nil
}

func (r *ElfReader) ReadRelocs() error {
	var err error
	if r.symCount, err = calculateSymbolCount(r.File, r.dynMap); err != nil {
		return fmt.Errorf("failed to calculate symbol count: %w", err)
	}

	logInfo(cText("* Found "), fValue(r.symCount), cText(" symbols"))
	r.Symbols = make([]SymbolEntry, r.symCount)
	if r.symCount > 0 && r.symtabOffset != 0 {
		if _, err := r.File.Seek(int64(r.symtabOffset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to symbol table: %w", err)
		}
		if err := binary.Read(r.File, binary.LittleEndian, r.Symbols); err != nil {
			logDebug(cWarning("   -> Warning: failed to read symbol table: "), cText(err.Error()))
		}
	}

	if r.relOffset != 0 {
		relCount := r.relSize / 16
		logInfo(cText(" + DT_REL at "), fAddress(r.relOffset), cText(" count="), fValue(relCount))
		r.Rel = make([]RelEntry,relCount)
		if _, err = r.File.Seek(int64(r.relOffset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to rel table: %w", err)
		}
		if err = binary.Read(r.File, binary.LittleEndian, r.Rel); err != nil {
			return fmt.Errorf("failed to read rel table: %w", err)
		}
	}
	if r.relaOffset != 0 {
		relaCount := r.relaSize / 24
		logInfo(cText(" + DT_RELA at "), fAddress(r.relaOffset), cText(" count="), fValue(relaCount))
		r.Rela = make([]RelaEntry, relaCount)
		if _, err = r.File.Seek(int64(r.relaOffset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to rela table: %w", err)
		}
		if err = binary.Read(r.File, binary.LittleEndian, r.Rela); err != nil {
			return fmt.Errorf("failed to read rela table: %w", err)
		}
	}
	if r.jmprelOffset != 0 {
		if r.jmprelEntry == 16 {
			jmprelCount := r.jmprelSize / 16
			logInfo(cText(" + DT_JMPREL at "), fAddress(r.jmprelOffset), cText(" count="), fValue(jmprelCount))
			r.JmpRel = make([]RelEntry, jmprelCount)
			if _, err = r.File.Seek(int64(r.jmprelOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to jmprel table: %w", err)
			}
			if err = binary.Read(r.File, binary.LittleEndian, r.JmpRel); err != nil {
				return fmt.Errorf("failed to read jmprel table: %w", err)
			}
		} else {
			jmprelCount := r.jmprelSize / 24
			logInfo(cText(" + DT_JMPREL at "), fAddress(r.jmprelOffset), cText(" count="), fValue(jmprelCount))
			r.JmpRela = make([]RelaEntry, jmprelCount)
			if _, err = r.File.Seek(int64(r.jmprelOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to jmprel table: %w", err)
			}
			if err = binary.Read(r.File, binary.LittleEndian, r.JmpRela); err != nil {
				return fmt.Errorf("failed to read jmprel table: %w", err)
			}
		}
	}

	return nil
}

func (r *ElfReader) FixRelocs(base uint64) error {
	fnRel := func (rel *RelEntry) {
		relocType := rel.Type()
		relocSym := rel.Sym()

		prel := (base - r.phdrPtLoadPageStart) + rel.Offset
		if relocType == R_AARCH64_RELATIVE {
			if _, err := r.File.Seek(int64(rel.Offset), io.SeekStart); err != nil {
			}
			if err := binary.Read(r.File, binary.LittleEndian, &prel); err != nil {
			}
		}
		if prel >= base {
			prel = prel - base
		}
		rsym := r.Symbols[relocSym]
		if rsym.St_Value != 0 {
			prel = rsym.St_Value
		}
		rname := readStrtabString(r.File, r.strtabOffset, rsym.St_Name)
		rel.Offset = prel

		logDebug(cText("    - rel "), cValue(relocType.Text()), cText(" "), cValue(rname), cText(" prel "), fAddress(prel))
	}
	fnRela := func(rela *RelaEntry) {
		relocType := rela.Type()
		relocSym := rela.Sym()

		prela := (base - r.phdrPtLoadPageStart) + rela.Offset
		if relocType == R_AARCH64_RELATIVE {
			prela = uint64(rela.Addend)
		}
		if prela >= base {
			prela = prela - base
		}
		rsym := r.Symbols[relocSym]
		if rsym.St_Value != 0 {
			prela = rsym.St_Value
		}
		rname := readStrtabString(r.File, r.strtabOffset, rsym.St_Name)
		rela.Offset = prela
		logDebug(cText("    - rela "), cValue(relocType.Text()), cText(" "), cValue(rname), cText(" prel "), fAddress(prela))

	}

	for _, rel := range r.Rel {
		fnRel(&rel)
	}
	for _, rela := range r.Rela {
		fnRela(&rela)
	}
	for _, jmprel := range r.JmpRel {
		fnRel(&jmprel)
	}
	for _, jmprela := range r.JmpRela {
		fnRela(&jmprela)
	}

	return nil
}

// rebuildSectionHeaders reconstructs the Section Header Table and writes it to the end of the file.
func rebuildSectionHeaders(filePath string, file *os.File, header *ELFHeader, phdrs []ProgramHeader, baseAddr uint64) error {
	// 1. Read the fixed dynamic section to gather info
	var dynamicPhdr *ProgramHeader
	for i := range phdrs {
		if phdrs[i].Type == PT_DYNAMIC {
			dynamicPhdr = &phdrs[i]
			break
		}
	}

	if dynamicPhdr == nil {
		return fmt.Errorf("PT_DYNAMIC segment not found, cannot rebuild SHT")
	}

	entryCount := dynamicPhdr.Memsz / 16
	dynamicEntries := make([]DynamicEntry, entryCount)
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section for SHT info: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section for SHT info: %w", err)
	}

	// Map to hold dynamic values
	dynMap := make(map[DT_Tag]uint64)
	for _, entry := range dynamicEntries {
		dynMap[entry.Tag] = entry.Val
	}

	vaddrToOffset := func(vaddr uint64) uint64 {
		for i := range phdrs {
			phdr := &phdrs[i]
			if phdr.Type == PT_LOAD {
				if vaddr >= phdr.Vaddr && vaddr < phdr.Vaddr+phdr.Memsz {
					offset := vaddr - phdr.Vaddr + phdr.Offset
					return offset
				}
			}
		}
		// If not found in any PT_LOAD, assume it's already a file offset or equals vaddr
		return vaddr
	}

	// 2. Calculate symbol count
	symCount, err := calculateSymbolCount(file, dynMap)
	if err != nil {
		if symCount == 0 {
			return fmt.Errorf("failed to calculate symbol count: %w", err)
		}
	}
	logInfo(cText("found "), fValue(symCount), cText(" symbols"))

	// 3. Initialize section collection
	sections := []SectionInfo{
		{Name: "", Type: SHT_NULL, Addralign: 1}, // Null section at index 0
	}
	shstrtab := "\x00"
	shNameOffsets := make(map[string]uint32)

	addShStr := func(name string) uint32 {
		if offset, ok := shNameOffsets[name]; ok {
			return offset
		}
		offset := uint32(len(shstrtab))
		shstrtab += name + "\x00"
		shNameOffsets[name] = offset
		return offset
	}

	// 4. Collect sections in memory address order to preserve layout
	type sectionCandidate struct {
		info     SectionInfo
		priority int // Lower priority = earlier in file
	}

	candidates := []sectionCandidate{}

	// Helper to add candidate
	addCandidate := func(name string, sType uint32, flags uint64, vaddr, size, align, entsize uint64, priority int) {
		if size == 0 && sType != SHT_NULL && sType != SHT_NOBITS {
			return
		}
		offset := vaddrToOffset(vaddr)
		candidates = append(candidates, sectionCandidate{
			info: SectionInfo{
				Name:      name,
				Type:      sType,
				Flags:     flags,
				Addr:      vaddr,
				Offset:    offset,
				Size:      size,
				Addralign: align,
				Entsize:   entsize,
			},
			priority: priority,
		})
	}

	// Add sections in typical ELF order with priorities

	// PT_NOTE sections (priority 10)
	for i := range phdrs {
		if phdrs[i].Type == PT_NOTE && phdrs[i].Filesz > 0 {
			addCandidate(".note", SHT_NOTE, SHF_ALLOC, phdrs[i].Vaddr, phdrs[i].Filesz, phdrs[i].Align, 0, 10)
			break
		}
	}

	// GNU Hash (priority 20)
	if dynMap[DT_GNU_HASH] != 0 {
		gnuHashSize, err := calculateGnuHashSize(file, dynMap[DT_GNU_HASH], symCount)
		if err == nil && gnuHashSize > 0 {
			addCandidate(".gnu.hash", SHT_GNU_HASH, SHF_ALLOC, dynMap[DT_GNU_HASH], gnuHashSize, 8, 4, 20)
		}
	}

	// Classic Hash (priority 21) - older ELF hash table
	if dynMap[DT_HASH] != 0 {
		hashSize, err := calculateHashSize(file, dynMap[DT_HASH])
		if err == nil && hashSize > 0 {
			addCandidate(".hash", SHT_HASH, SHF_ALLOC, dynMap[DT_HASH], hashSize, 8, 4, 21)
		}
	}

	// Dynsym (priority 30)
	if dynMap[DT_SYMTAB] != 0 && dynMap[DT_SYMENT] != 0 && symCount > 0 {
		symtabSize := symCount * dynMap[DT_SYMENT]
		addCandidate(".dynsym", SHT_DYNSYM, SHF_ALLOC, dynMap[DT_SYMTAB], symtabSize, 8, dynMap[DT_SYMENT], 30)
	}

	// Dynstr (priority 40)
	if dynMap[DT_STRTAB] != 0 && dynMap[DT_STRSZ] != 0 {
		addCandidate(".dynstr", SHT_STRTAB, SHF_ALLOC, dynMap[DT_STRTAB], dynMap[DT_STRSZ], 1, 0, 40)
	}

	// Version sections (priority 50-52)
	if dynMap[DT_VERSYM] != 0 && symCount > 0 {
		versymSize := symCount * 2
		addCandidate(".gnu.version", SHT_GNU_VERSYM, SHF_ALLOC, dynMap[DT_VERSYM], versymSize, 2, 2, 50)
	}
	if dynMap[DT_VERNEED] != 0 && dynMap[DT_VERNEEDNUM] > 0 {
		verneedSize := dynMap[DT_VERNEEDNUM] * (24 + 2*16)
		addCandidate(".gnu.version_r", SHT_GNU_VERNEED, SHF_ALLOC, dynMap[DT_VERNEED], verneedSize, 8, 0, 52)
	}

	// Relocations (priority 60-62)
	// DT_REL (without addend) - used on some 32-bit architectures
	if dynMap[DT_REL] != 0 && dynMap[DT_RELSZ] != 0 {
		addCandidate(".rel.dyn", SHT_REL, SHF_ALLOC, dynMap[DT_REL], dynMap[DT_RELSZ], 8, 16, 60)
	}
	// DT_RELA (with addend) - used on 64-bit architectures like ARM64
	if dynMap[DT_RELA] != 0 && dynMap[DT_RELASZ] != 0 {
		addCandidate(".rela.dyn", SHT_RELA, SHF_ALLOC, dynMap[DT_RELA], dynMap[DT_RELASZ], 8, 24, 60)
	}
	// DT_JMPREL can be either REL or RELA depending on DT_PLTREL
	if dynMap[DT_JMPREL] != 0 && dynMap[DT_PLTRELSZ] != 0 {
		// Check DT_PLTREL to determine the type (DT_REL=17 or DT_RELA=7)
		pltRelType := dynMap[DT_PLTREL]
		if pltRelType == uint64(DT_REL) {
			addCandidate(".rel.plt", SHT_REL, SHF_ALLOC|SHF_INFO_LINK, dynMap[DT_JMPREL], dynMap[DT_PLTRELSZ], 8, 16, 61)
		} else {
			// Default to RELA (most common for 64-bit)
			addCandidate(".rela.plt", SHT_RELA, SHF_ALLOC|SHF_INFO_LINK, dynMap[DT_JMPREL], dynMap[DT_PLTRELSZ], 8, 24, 61)
		}
	}

	// Find executable and writable segments
	var execPhdr, rwPhdr, tlsPhdr *ProgramHeader
	for i := range phdrs {
		phdr := &phdrs[i]
		if phdr.Type == PT_LOAD {
			if (phdr.Flags&SHF_EXECINSTR) != 0 && (phdr.Flags&SHF_WRITE) == 0 {
				execPhdr = phdr
			}
			if (phdr.Flags & SHF_WRITE) != 0 {
				rwPhdr = phdr
			}
		}
		if phdr.Type == PT_TLS {
			tlsPhdr = phdr
		}
	}

	// PLT (priority 70)
	if dynMap[DT_PLTGOT] != 0 && dynMap[DT_PLTRELSZ] != 0 && execPhdr != nil {
		pltRelocCount := dynMap[DT_PLTRELSZ] / 24
		pltSize := 32 + (pltRelocCount * 16)
		pltAddr := execPhdr.Vaddr
		addCandidate(".plt", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, pltAddr, pltSize, 16, 16, 70)
	}

	// Text section (priority 80)
	if execPhdr != nil {
		// Find where known sections end in exec segment
		execEnd := execPhdr.Vaddr
		for _, cand := range candidates {
			if cand.info.Addr >= execPhdr.Vaddr && cand.info.Addr < execPhdr.Vaddr+execPhdr.Filesz {
				candEnd := cand.info.Addr + cand.info.Size
				if candEnd > execEnd {
					execEnd = candEnd
				}
			}
		}

		textStart := alignUp(execEnd, 16)
		textEnd := execPhdr.Vaddr + execPhdr.Filesz
		if textEnd > textStart {
			addCandidate(".text", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, textStart, textEnd-textStart, 16, 0, 80)
		}
	}

	// EH Frame (priority 90)
	for i := range phdrs {
		if phdrs[i].Type == PT_GNU_EH_FRAME && phdrs[i].Filesz > 0 {
			addCandidate(".eh_frame", SHT_PROGBITS, SHF_ALLOC, phdrs[i].Vaddr, phdrs[i].Filesz, 4, 0, 90)
			break
		}
	}

	// TLS sections (priority 100-101)
	if tlsPhdr != nil && tlsPhdr.Memsz > 0 {
		if tlsPhdr.Filesz > 0 {
			addCandidate(".tdata", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, tlsPhdr.Vaddr, tlsPhdr.Filesz, tlsPhdr.Align, 0, 100)
		}
		if tlsPhdr.Memsz > tlsPhdr.Filesz {
			addCandidate(".tbss", SHT_NOBITS, SHF_ALLOC|SHF_WRITE, tlsPhdr.Vaddr+tlsPhdr.Filesz, tlsPhdr.Memsz-tlsPhdr.Filesz, tlsPhdr.Align, 0, 101)
		}
	}

	// Init/Fini arrays (priority 110-111)
	if dynMap[DT_INIT_ARRAY] != 0 && dynMap[DT_INIT_ARRAYSZ] != 0 {
		addCandidate(".init_array", SHT_INIT_ARRAY, SHF_ALLOC|SHF_WRITE, dynMap[DT_INIT_ARRAY], dynMap[DT_INIT_ARRAYSZ], 8, 8, 110)
	}
	if dynMap[DT_FINI_ARRAY] != 0 && dynMap[DT_FINI_ARRAYSZ] != 0 {
		addCandidate(".fini_array", SHT_FINI_ARRAY, SHF_ALLOC|SHF_WRITE, dynMap[DT_FINI_ARRAY], dynMap[DT_FINI_ARRAYSZ], 8, 8, 111)
	}

	// Dynamic section (priority 120)
	addCandidate(".dynamic", SHT_DYNAMIC, SHF_ALLOC|SHF_WRITE, dynamicPhdr.Vaddr, dynamicPhdr.Memsz, dynamicPhdr.Align, 16, 120)

	// GOT sections (priority 130-131)
	if dynMap[DT_PLTGOT] != 0 && rwPhdr != nil {
		// Calculate .got.plt size: 3 reserved entries + PLT relocations
		pltRelocCount := dynMap[DT_PLTRELSZ] / 24
		gotPltSize := (pltRelocCount + 3) * 8

		// Add .got.plt section
		if gotPltSize > 0 {
			addCandidate(".got.plt", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, dynMap[DT_PLTGOT], gotPltSize, 8, 8, 130)
		}

		// Add .got section (comes before .got.plt in memory, typically)
		// The .got ends where .got.plt begins
		if dynMap[DT_PLTGOT] > rwPhdr.Vaddr {
			// Find where .got actually starts - typically after .dynamic
			gotStart := dynamicPhdr.Vaddr + dynamicPhdr.Memsz
			gotStart = alignUp(gotStart, 8)

			// If there's space between .dynamic and .got.plt, that's .got
			if gotStart < dynMap[DT_PLTGOT] {
				gotSize := dynMap[DT_PLTGOT] - gotStart
				addCandidate(".got", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, gotStart, gotSize, 8, 8, 131)
			}
		}
	}

	// Data section (priority 140)
	if rwPhdr != nil {
		// Find end of last known writable section
		rwEnd := rwPhdr.Vaddr
		for _, cand := range candidates {
			if cand.info.Addr >= rwPhdr.Vaddr && cand.info.Addr < rwPhdr.Vaddr+rwPhdr.Filesz {
				candEnd := cand.info.Addr + cand.info.Size
				if candEnd > rwEnd {
					rwEnd = candEnd
				}
			}
		}

		dataStart := alignUp(rwEnd, 16)
		dataEnd := rwPhdr.Vaddr + rwPhdr.Filesz
		if dataEnd > dataStart {
			addCandidate(".data", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, dataStart, dataEnd-dataStart, 16, 0, 140)
		}

		// BSS section (priority 150)
		bssStart := rwPhdr.Vaddr + rwPhdr.Filesz
		bssSize := rwPhdr.Memsz - rwPhdr.Filesz
		if bssSize > 0 {
			addCandidate(".bss", SHT_NOBITS, SHF_ALLOC|SHF_WRITE, bssStart, bssSize, 16, 0, 150)
		}
	}

	// Sort candidates by address first, then priority
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].info.Addr != candidates[j].info.Addr {
			return candidates[i].info.Addr < candidates[j].info.Addr
		}
		return candidates[i].priority < candidates[j].priority
	})

	// 5. Calculate proper file offsets with alignment
	var currentOffset uint64 = 0

	// Find the maximum offset used by PT_LOAD segments
	for _, phdr := range phdrs {
		if phdr.Type == PT_LOAD {
			end := phdr.Offset + phdr.Filesz
			if end > currentOffset {
				currentOffset = end
			}
		}
	}

	// Add sections with properly aligned offsets
	for _, cand := range candidates {
		sec := cand.info

		// For SHT_NOBITS, offset doesn't matter (no file space)
		if sec.Type == SHT_NOBITS {
			sec.Offset = sec.Addr
		} else {
			// Align offset according to section alignment
			currentOffset = alignUp(currentOffset, sec.Addralign)
			sec.Offset = currentOffset
			currentOffset += sec.Size
		}

		sections = append(sections, sec)
	}

	// 6. Build .symtab and .strtab from .dynsym
	var dynsymOffset, dynstrOffset uint64
	if dynMap[DT_SYMTAB] != 0 && dynMap[DT_SYMENT] != 0 && symCount > 0 {
		dynsymOffset = dynMap[DT_SYMTAB]
	}
	if dynMap[DT_STRTAB] != 0 {
		dynstrOffset = dynMap[DT_STRTAB]
	}

	// Build .symtab and .strtab
	var symtabEntries []SymbolEntry
	var strtabData string = "\x00" // Start with null byte
	strtabOffsets := make(map[string]uint32)

	addString := func(s string) uint32 {
		if s == "" {
			return 0
		}
		if offset, ok := strtabOffsets[s]; ok {
			return offset
		}
		offset := uint32(len(strtabData))
		strtabData += s + "\x00"
		strtabOffsets[s] = offset
		return offset
	}

	// Add null symbol
	symtabEntries = append(symtabEntries, SymbolEntry{})

	// Read dynsym and copy/fix symbols
	if dynsymOffset != 0 && symCount > 0 {
		dynsyms := make([]SymbolEntry, symCount)
		if _, err := file.Seek(int64(dynsymOffset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to dynsym: %w", err)
		}
		if err := binary.Read(file, binary.LittleEndian, &dynsyms); err != nil {
			return fmt.Errorf("failed to read dynsym: %w", err)
		}

		localCount := uint32(1) // Start after null symbol
		globalSymbols := []SymbolEntry{}

		for _, sym := range dynsyms {
			if sym.St_Name == 0 && sym.St_Value == 0 && sym.St_Size == 0 {
				continue // Skip null entries
			}

			// Read symbol name
			symName := readStrtabString(file, dynstrOffset, sym.St_Name)

			// Fix symbol value (remove base address)
			if sym.St_Value >= baseAddr {
				sym.St_Value -= baseAddr
			}

			// Update name offset in new strtab
			sym.St_Name = addString(symName)

			// Separate local and global symbols
			if sym.stBind() == STB_LOCAL {
				symtabEntries = append(symtabEntries, sym)
				localCount++
			} else {
				globalSymbols = append(globalSymbols, sym)
			}
		}

		// Add global symbols after local ones
		symtabEntries = append(symtabEntries, globalSymbols...)

		logInfo(cText("Built .symtab with "), fValue(len(symtabEntries)), cText(" symbols ("), fValue(localCount), cText(" local)"))
	}

	// Add .strtab section (priority 160)
	strtabSectionIdx := len(sections)
	currentOffset = alignUp(currentOffset, 1)
	sections = append(sections, SectionInfo{
		Name:      ".strtab",
		Type:      SHT_STRTAB,
		Offset:    currentOffset,
		Size:      uint64(len(strtabData)),
		Addralign: 1,
	})
	currentOffset += uint64(len(strtabData))

	// Add .symtab section (priority 161)
	symtabSectionIdx := len(sections)
	currentOffset = alignUp(currentOffset, 8)
	symtabSize := uint64(len(symtabEntries)) * uint64(binary.Size(SymbolEntry{}))
	sections = append(sections, SectionInfo{
		Name:      ".symtab",
		Type:      SHT_SYMTAB,
		Offset:    currentOffset,
		Size:      symtabSize,
		Link:      uint32(strtabSectionIdx),
		Info:      1, // Will be updated with local symbol count
		Addralign: 8,
		Entsize:   uint64(binary.Size(SymbolEntry{})),
	})
	currentOffset += symtabSize

	// Update .symtab info with local symbol count
	localCount := uint32(1)
	for i := 1; i < len(symtabEntries); i++ {
		if symtabEntries[i].stBind() != STB_LOCAL {
			break
		}
		localCount++
	}
	sections[symtabSectionIdx].Info = localCount

	// 7. Add .shstrtab section
	shstrtabSectionIndex := uint32(len(sections))
	currentOffset = alignUp(currentOffset, 1)
	sections = append(sections, SectionInfo{
		Name:      ".shstrtab",
		Type:      SHT_STRTAB,
		Offset:    currentOffset,
		Size:      0, // Will be set after building string table
		Addralign: 1,
	})

	// 8. Populate section names in shstrtab
	nameToIndex := make(map[string]uint32)
	for i := range sections {
		if sections[i].Name != "" {
			nameToIndex[sections[i].Name] = uint32(i)
			addShStr(sections[i].Name)
		}
	}

	// 9. Fix sh_link and sh_info
	dynsymIndex := nameToIndex[".dynsym"]
	dynstrIndex := nameToIndex[".dynstr"]
	textIndex := nameToIndex[".text"]

	for i := range sections {
		sec := &sections[i]
		switch sec.Name {
		case ".dynsym":
			sec.Link = dynstrIndex
			sec.Info = 1
		case ".hash":
			sec.Link = dynsymIndex
		case ".gnu.hash":
			sec.Link = dynsymIndex
		case ".dynamic":
			sec.Link = dynstrIndex
		case ".rela.dyn", ".rel.dyn":
			sec.Link = dynsymIndex
		case ".rela.plt", ".rel.plt":
			sec.Link = dynsymIndex
			sec.Info = textIndex // Link to .plt or .text
		case ".gnu.version":
			sec.Link = dynsymIndex
		case ".gnu.version_r":
			sec.Link = dynstrIndex
		}
	}
	// 9. Finalize .shstrtab
	shstrtabSection := &sections[shstrtabSectionIndex]
	shstrtabSection.Size = uint64(len(shstrtab))

	// 10. Calculate SHT position (aligned to 8 bytes)
	shdrTableOffset := alignUp(shstrtabSection.Offset+shstrtabSection.Size, 8)
	shdrTableSize := uint64(len(sections)) * uint64(binary.Size(SectionHeader{}))

	logDebug(cText("   -> Writing SHT at offset "), fAddress(shdrTableOffset),
		cText(", size "), cValue(shdrTableSize),
		cText(", sections "), cValue(len(sections)))

	// 11. Extend file to accommodate SHT
	if err := os.Truncate(filePath, int64(shdrTableOffset+shdrTableSize)); err != nil {
		return fmt.Errorf("failed to truncate file for SHT: %w", err)
	}

	// 12. Write .shstrtab
	if _, err := file.Seek(int64(shstrtabSection.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to .shstrtab offset: %w", err)
	}
	if _, err := file.Write([]byte(shstrtab)); err != nil {
		return fmt.Errorf("failed to write .shstrtab: %w", err)
	}

	// 13. Write SHT
	if _, err := file.Seek(int64(shdrTableOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to SHT offset: %w", err)
	}

	for i := range sections {
		sec := &sections[i]
		shdr := SectionHeader{
			Name:      addShStr(sec.Name),
			Type:      sec.Type,
			Flags:     sec.Flags,
			Addr:      sec.Addr,
			Offset:    sec.Offset,
			Size:      sec.Size,
			Link:      sec.Link,
			Info:      sec.Info,
			Addralign: sec.Addralign,
			Entsize:   sec.Entsize,
		}

		if err := binary.Write(file, binary.LittleEndian, shdr); err != nil {
			return fmt.Errorf("failed to write section header %s: %w", sec.Name, err)
		}
	}

	// 14. Update ELF header
	header.ShdrOffset = shdrTableOffset
	header.Shentsize = uint16(binary.Size(SectionHeader{}))
	header.Shnum = uint16(len(sections))
	header.Shstrndx = uint16(shstrtabSectionIndex)

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to EHDR offset: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// calculateSymbolCount reads the GNU Hash table and determines the total number of symbols.
func calculateSymbolCount(file *os.File, dynMap map[DT_Tag]uint64) (uint64, error) {
	hashOffset := dynMap[DT_HASH]
	gnuHashOffset := dynMap[DT_GNU_HASH]
	symtabOffset := dynMap[DT_SYMTAB]
	symEntSize := dynMap[DT_SYMENT]

	if hashOffset != 0 {
		var header HashHeader
		logInfo("using DT_HASH")

		if _, err := file.Seek(int64(hashOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to hash table: %w", err)
		}
		if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("failed to read hash header: %w", err)
		}

		return uint64(header.Nchain), nil
	}

	if gnuHashOffset != 0 {
		// 1. Read GNU Hash Header
		var header GNUHashHeader
		logInfo("using DT_GNU_HASH")

		if _, err := file.Seek(int64(gnuHashOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to GNU hash table: %w", err)
		}
		if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("failed to read GNU hash header: %w", err)
		}

		// 2. Calculate pointers to buckets and chains
		bloomSize := header.Maskwords * 8
		bucketsOffset := gnuHashOffset + 16 + uint64(bloomSize)
		chainsOffset := bucketsOffset + uint64(header.Nbuckets*4)

		// 3. Read Buckets
		buckets := make([]uint32, header.Nbuckets)
		if _, err := file.Seek(int64(bucketsOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to GNU hash buckets: %w", err)
		}
		if err := binary.Read(file, binary.LittleEndian, &buckets); err != nil {
			return 0, fmt.Errorf("failed to read GNU hash buckets: %w", err)
		}

		// 4. Find max symbol index
		maxSymIndex := uint64(header.Symndx)

		// Seek to chains start
		if _, err := file.Seek(int64(chainsOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to GNU hash chains: %w", err)
		}

		// Read all chain data at once (more efficient)
		maxChainSize := 100000 * 4 // 400KB buffer
		chainBuf := make([]byte, maxChainSize)
		n, err := file.Read(chainBuf)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("failed to read GNU hash chains: %w", err)
		}
		chainBuf = chainBuf[:n]

		chainCache := make(map[uint32]bool)

		for _, bucketIndex := range buckets {
			if bucketIndex < header.Symndx || bucketIndex == 0 {
				continue
			}

			if chainCache[bucketIndex] {
				continue
			}

			chainCache[bucketIndex] = true
			currentSymIndex := uint64(bucketIndex)

			for {
				chainIndex := currentSymIndex - uint64(header.Symndx)
				byteOffset := chainIndex * 4

				if byteOffset+4 > uint64(len(chainBuf)) {
					break
				}

				if currentSymIndex > maxSymIndex {
					maxSymIndex = currentSymIndex
				}

				chainVal := binary.LittleEndian.Uint32(chainBuf[byteOffset : byteOffset+4])
				if chainVal&1 != 0 {
					break
				}
				currentSymIndex++
			}
		}

		return maxSymIndex + 1, nil
	}


	if symtabOffset != 0 && dynMap[DT_STRSZ] != 0 {
		return (dynMap[DT_STRSZ] / 10) * symEntSize, nil
	}

	return 0, fmt.Errorf("missing DT_HASH or DT_GNU_HASH or DT_SYMTAB/DT_SYMENT")
}

// calculateGnuHashSize calculates the total size of the .gnu.hash section.
func calculateGnuHashSize(file *os.File, gnuHashOffset uint64, symCount uint64) (uint64, error) {
	if gnuHashOffset == 0 {
		return 0, fmt.Errorf("invalid .gnu.hash offset")
	}

	// 1. Read GNU Hash Header
	var header GNUHashHeader
	if _, err := file.Seek(int64(gnuHashOffset), io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to GNU hash table: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
		return 0, fmt.Errorf("failed to read GNU hash header: %w", err)
	}

	// 2. Calculate the total size
	bloomSize := uint64(header.Maskwords) * 8
	bucketsSize := uint64(header.Nbuckets) * 4
	chainsSize := (symCount - uint64(header.Symndx)) * 4

	totalSize := uint64(16) + bloomSize + bucketsSize + chainsSize
	return totalSize, nil
}

// calculateHashSize calculates the total size of the classic .hash section.
func calculateHashSize(file *os.File, hashOffset uint64) (uint64, error) {
	if hashOffset == 0 {
		return 0, fmt.Errorf("invalid .hash offset")
	}

	// Read the header (nbucket and nchain)
	var nbucket, nchain uint32
	if _, err := file.Seek(int64(hashOffset), io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to hash table: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &nbucket); err != nil {
		return 0, fmt.Errorf("failed to read nbucket: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &nchain); err != nil {
		return 0, fmt.Errorf("failed to read nchain: %w", err)
	}

	// Calculate total size: header (8 bytes) + buckets + chains
	totalSize := uint64(8 + (nbucket * 4) + (nchain * 4))
	return totalSize, nil
}

// fixRelocations reads the relocation tables and fixes the pointers they reference.
func fixRelocations(file *os.File, phdrs []ProgramHeader, baseAddr uint64) error {
	var dynamicPhdr *ProgramHeader
	for i := range phdrs {
		if phdrs[i].Type == PT_DYNAMIC {
			dynamicPhdr = &phdrs[i]
			break
		}
	}

	if dynamicPhdr == nil {
		return nil
	}

	// Read the fixed dynamic section to get relocation table info
	entryCount := dynamicPhdr.Memsz / uint64(binary.Size(DynamicEntry{}))
	dynamicEntries := make([]DynamicEntry, entryCount)
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section for reading: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section for relocation info: %w", err)
	}


	dynMap := make(map[DT_Tag]uint64)
	var strtabOffset, symtabOffset, relOffset, relSize, relaOffset, relaSize, jmprelOffset, jmprelSize, jmprelEntry uint64
	for _, entry := range dynamicEntries {
		switch entry.Tag {
		case DT_STRTAB:
			strtabOffset = entry.Val
		case DT_SYMTAB:
			symtabOffset = entry.Val
		case DT_REL:
			relOffset = entry.Val
		case DT_RELSZ:
			relSize = entry.Val
		case DT_RELA:
			relaOffset = entry.Val
		case DT_RELASZ:
			relaSize = entry.Val
		case DT_JMPREL:
			jmprelOffset = entry.Val
		case DT_PLTREL:
			if entry.Val == uint64(DT_REL) {
				jmprelEntry = uint64(binary.Size(RelEntry{}))
			} else {
				jmprelEntry = uint64(binary.Size(RelaEntry{}))
			}
		case DT_PLTRELSZ:
			jmprelSize = entry.Val
		}
		dynMap[entry.Tag] = entry.Val
	}


	// 2. Calculate symbol count
	symCount, err := calculateSymbolCount(file, dynMap)
	if err != nil {
		logInfo(cWarning("   -> Warning: could not calculate symbol count: "), cText(err.Error()))
		symCount = 0
	} else {
		logInfo(cText("    -> found "), fValue(symCount), cText(" symbols"))
	}

	// Cache symbol table
	symbols := make([]SymbolEntry, symCount)
	if symCount > 0 && symtabOffset != 0 {
		if _, err := file.Seek(int64(symtabOffset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to symbol table: %w", err)
		}
		if err := binary.Read(file, binary.LittleEndian, &symbols); err != nil {
			logDebug(cWarning("   -> Warning: failed to read symbol table: "), cText(err.Error()))
		}
	}

	readSymbolName := func(i uint64) (string, error) {
		if i >= uint64(len(symbols)) {
			return "", fmt.Errorf("symbol index %d out of range", i)
		}
		return readStrtabString(file, strtabOffset, symbols[i].St_Name), nil
	}

	processRelocTable := func (offset, size uint64, isRela bool) error {
		if size == 0 {
			return nil
		}

		entrySize := uint64(16)
		if isRela { entrySize = 24 }

		if size%entrySize != 0 {
			tableType := "REL"
			if isRela { tableType = "RELA" }
			return fmt.Errorf("%s table size 0x%x is not a multiple of entry size 0x%x", tableType, size, entrySize)
		}
		numEntries := size / entrySize

		// Seek to the start of the relocation table
		if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to relocation table at 0x%x: %w", offset, err)
		}

		// Read the entire table into a buffer/slice of bytes
		relocTableBytes := make([]byte, size)
		if _, err := io.ReadFull(file, relocTableBytes); err != nil {
			return fmt.Errorf("failed to read relocation table at 0x%x: %w", offset, err)
		}

		// Process each entry
		for i := range numEntries {
			entryOffset := i * entrySize
			// Use binary.Read on a sub-slice or directly access bytes to get Offset and Info
			relocOffset := binary.LittleEndian.Uint64(relocTableBytes[entryOffset : entryOffset+8])
			relocInfo := binary.LittleEndian.Uint64(relocTableBytes[entryOffset+8 : entryOffset+16])

			relocType := RelocationType(relocInfo & 0xFFFFFFFF) // Extract relocation type
			relocSym := relocInfo >> 32

			var addend int64 = 0
			if isRela {
				addend = int64(binary.LittleEndian.Uint64(relocTableBytes[entryOffset+16 : entryOffset+24]))
			}

			// Read current value at relocation target
			var currentVal uint64
			if _, err := file.Seek(int64(relocOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to relocation target 0x%x: %w", relocOffset, err)
			}
			if err := binary.Read(file, binary.LittleEndian, &currentVal); err != nil {
				return fmt.Errorf("failed to read relocation target at 0x%x: %w", relocOffset, err)
			}

			// Calculate the fixed value based on relocation type
			var fixedVal uint64

			switch relocType {
			case R_AARCH64_RELATIVE:
				// B + A (base + addend)
				if isRela {
					fixedVal = uint64(addend)
				} else {
					fixedVal = currentVal
				}
				// Remove base address if present
				if fixedVal >= baseAddr {
					fixedVal -= baseAddr
				}

			case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT,  R_AARCH64_ABS64:
				fixedVal = currentVal
				if fixedVal >= baseAddr {
					fixedVal -= baseAddr
				}
				// // S + A (symbol + addend)
				// if relocSym < uint64(len(symbols)) {
				// 	symbol := symbols[relocSym]
				// 	fixedVal = symbol.St_Value + uint64(addend)
				// 	// Remove base address if present
				// 	if fixedVal >= baseAddr {
				// 		fixedVal -= baseAddr
				// 	}
				// } else {
				// 	fixedVal = currentVal
				// }
			default:
				// For unknown types, keep current value
				fixedVal = currentVal
			}

			var symFormat string = fValue(relocSym)
			if symName, _ := readSymbolName(relocSym); symName != "" {
				symFormat = cValue(symName)
			}
			logDebug(cText("     - relocation "), cValue(relocType.Text()),
				cText(" at "), fAddress(relocOffset),
				cText(" symbol "), symFormat,
				cText(" current="), fAddress(currentVal),
				cText(" fixed="), fAddress(fixedVal))

			// Write the fixed value back
			if _, err := file.Seek(int64(relocOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to relocation target 0x%x for writing: %w", relocOffset, err)
			}
			if err := binary.Write(file, binary.LittleEndian, fixedVal); err != nil {
				return fmt.Errorf("failed to write fixed relocation target at 0x%x: %w", relocOffset, err)
			}
		}

		return nil
	}

	// Process DT_REL, DT_RELA and DT_JMPREL tables
	if relOffset != 0 {
		logDebug(cText("   -> DT_REL table at "), fAddress(relOffset), cText(", size="), cValue(relSize), cText(", entries="), cValue(relSize/16))
		if err := processRelocTable(relOffset, relSize, false); err != nil {
			return fmt.Errorf("DT_REL fix failed: %w", err)
		}
	}
	if relaOffset != 0 {
		logDebug(cText("   -> DT_RELA table at "), fAddress(relaOffset), cText(", size="), cValue(relaSize), cText(", entries="), cValue(relaSize/24))
		if err := processRelocTable(relaOffset, relaSize, true); err != nil {
			return fmt.Errorf("DT_RELA fix failed: %w", err)
		}
	}
	if jmprelOffset != 0 {
		logDebug(cText("   -> DT_JMPREL table at "), fAddress(jmprelOffset), cText(", size="), cValue(jmprelSize), cText(", entries="), cValue(jmprelSize/jmprelEntry))
		if err := processRelocTable(jmprelOffset, jmprelSize, jmprelEntry != 16); err != nil {
			return fmt.Errorf("DT_JMPREL fix failed: %w", err)
		}
	}

	return nil
}

// fixDynamicSection reads the dynamic section, fixes runtime pointers, and writes it back.
func fixDynamicSection(file *os.File, phdrs []ProgramHeader, baseAddr uint64) error {
	var dynamicPhdr *ProgramHeader
	for i := range phdrs {
		if phdrs[i].Type == PT_DYNAMIC {
			dynamicPhdr = &phdrs[i]
			break
		}
	}

	if dynamicPhdr == nil {
		return nil
	}

	entryCount := dynamicPhdr.Memsz / 16

	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero size")
	}
	logDebug(cText("   -> Dynamic section found p_vaddr="), fAddress(dynamicPhdr.Vaddr), cText(", p_offset="), fAddress(dynamicPhdr.Offset), cText(", entries="), fValue(entryCount))

	// Read the dynamic section content
	dynamicEntries := make([]DynamicEntry, entryCount)

	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section: %w", err)
	}

	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section: %w", err)
	}

	// Fix pointers in the dynamic section
	for i := range dynamicEntries {
		entry := &dynamicEntries[i]
		logInfo(cText("    - entry "), cValue(entry.Tag.Text()), cText(": "), fValue(entry.Val))

		switch entry.Tag {
		case DT_PLTGOT, DT_HASH, DT_GNU_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_REL, DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_VERNEED, DT_VERSYM:
			if entry.Val >= baseAddr {
				logDebug(cText("      + Fixing dynamic entry "), fValue(entry.Tag), cText(" to "), fAddress(entry.Val-baseAddr))
				entry.Val -= baseAddr
			}
		}
		if entry.Tag == DT_NULL {
			break
		}
	}

	// Rewrite the fixed dynamic section back to the file
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, dynamicEntries); err != nil {
		return fmt.Errorf("failed to write fixed dynamic section: %w", err)
	}

	return nil
}

// fixProgramHeaders implements the core logic to fix the program headers.
func fixProgramHeaders(file *os.File, header *ELFHeader, phdrs []ProgramHeader, baseAddr uint64) error {
	isRuntimeAddr := func(addr uint64) bool {
		return addr > 0x100000000
	}

	var firstLoadVaddr uint64 = 0
	for i := range phdrs {
		if phdrs[i].Type == PT_LOAD {
			firstLoadVaddr = phdrs[i].Vaddr
			break
		}
	}

	needsConversion := isRuntimeAddr(firstLoadVaddr)

	if needsConversion {
		logDebug(cWarning("   -> Detected runtime addresses"), cText("("), fAddress(firstLoadVaddr), cText("), applying conversion with base"), fAddress(baseAddr))
	} else {
		logDebug(cText("   -> Addresses appear relative, applying normalization only."))
	}

	for i := range phdrs {
		phdr := &phdrs[i]

		if phdr.Type == PT_LOAD {
			phdr.Filesz = phdr.Memsz
			phdr.Paddr = phdr.Vaddr
			phdr.Offset = phdr.Vaddr

			if needsConversion {
				if phdr.Vaddr < baseAddr {
					return fmt.Errorf("PT_LOAD segment Vaddr 0x%x is less than base address 0x%x", phdr.Vaddr, baseAddr)
				}
				relativeVaddr := phdr.Vaddr - baseAddr

				phdr.Offset = relativeVaddr
				phdr.Vaddr = relativeVaddr
				phdr.Paddr = relativeVaddr
			} else {
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
		}

		if phdr.Type == PT_PHDR {
			phdr.Vaddr = header.PhdrOffset
			phdr.Paddr = header.PhdrOffset
			phdr.Offset = header.PhdrOffset
		}

		if phdr.Type == PT_GNU_EH_FRAME || phdr.Type == PT_GNU_RELRO || phdr.Type == PT_GNU_STACK {
			if needsConversion {
				if phdr.Vaddr < baseAddr {
					return fmt.Errorf("GNU segment Vaddr 0x%x is less than base address 0x%x", phdr.Vaddr, baseAddr)
				}
				relativeVaddr := phdr.Vaddr - baseAddr
				phdr.Offset = relativeVaddr
				phdr.Vaddr = relativeVaddr
				phdr.Paddr = relativeVaddr
			} else {
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
			if phdr.Type == PT_GNU_RELRO {
				phdr.Filesz = phdr.Memsz
			}
		}

		if phdr.Type == PT_DYNAMIC {
			if needsConversion {
				if phdr.Vaddr < baseAddr {
					return fmt.Errorf("PT_DYNAMIC segment Vaddr 0x%x is less than base address 0x%x", phdr.Vaddr, baseAddr)
				}
				relativeVaddr := phdr.Vaddr - baseAddr
				phdr.Offset = relativeVaddr
				phdr.Vaddr = relativeVaddr
				phdr.Paddr = relativeVaddr
			} else {
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
		}
	}

	header.Type = ET_DYN
	header.Machine = EM_AARCH64

	return nil
}

func readStrtabString (file *os.File, strtabOffset uint64, nameOffset uint32) string {
		if nameOffset == 0 {
			return ""
		}

		// Get file size
		fileInfo, err := file.Stat()
		if err != nil {
			return ""
		}
		fileSize := fileInfo.Size()

		offset := strtabOffset + uint64(nameOffset)
		if offset >= uint64(fileSize) {
			return ""
		}

		// Seek to the string position
		_, err = file.Seek(int64(offset), io.SeekStart)
		if err != nil {
			return ""
		}

		// Read until null terminator or end of file
		var result []byte
		buf := make([]byte, 1)

		for {
			_, err := file.Read(buf)
			if err != nil || buf[0] == 0 {
				break
			}
			result = append(result, buf[0])
		}

		return string(result)
	}
