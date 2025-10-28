package sofixer

import (
	"encoding/binary"
	"fmt"
	"github.com/fatih/color"
	"io"
	"os"
	"sort"
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

const (
	ELFCLASS32 = 1
	ELFCLASS64 = 2

	PT_LOAD         = 1
	PT_DYNAMIC      = 2
	PT_INTERP       = 3
	PT_NOTE         = 4
	PT_PHDR         = 6
	PT_TLS          = 7
	PT_GNU_EH_FRAME = 0x6474e550
	PT_GNU_STACK    = 0x6474e551
	PT_GNU_RELRO    = 0x6474e552
	ET_DYN          = 3
	EM_AARCH64      = 183

	// Dynamic Tag Constants (DT_TAG)
	DT_NULL         = 0
	DT_NEEDED       = 1
	DT_PLTRELSZ     = 2
	DT_PLTGOT       = 3
	DT_HASH         = 4
	DT_STRTAB       = 5
	DT_SYMTAB       = 6
	DT_RELA         = 7
	DT_RELASZ       = 8
	DT_RELAENT      = 9
	DT_STRSZ        = 10
	DT_SYMENT       = 11
	DT_SONAME       = 14
	DT_JMPREL       = 23
	DT_INIT_ARRAY   = 25
	DT_FINI_ARRAY   = 26
	DT_INIT_ARRAYSZ = 27
	DT_FINI_ARRAYSZ = 28
	DT_FLAGS        = 30
	DT_GNU_HASH     = 0x6ffffef5
	DT_VERSYM       = 0x6ffffff0
	DT_FLAGS_1      = 0x6ffffffb
	DT_VERNEED      = 0x6ffffffe
	DT_VERNEEDNUM   = 0x6fffffff
	// AArch64 Relocation Types
	R_AARCH64_GLOB_DAT  = 1025
	R_AARCH64_JUMP_SLOT = 1026
	R_AARCH64_RELATIVE  = 1027

	// Section Header Types (SHT)
	SHT_NULL        = 0
	SHT_PROGBITS    = 1
	SHT_SYMTAB      = 2
	SHT_STRTAB      = 3
	SHT_RELA        = 4
	SHT_DYNAMIC     = 6
	SHT_NOTE        = 7
	SHT_NOBITS      = 8 // Added SHT_NOBITS
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
	Tag uint64 // Dynamic entry type
	Val uint64 // Value or pointer
}

// RelocationEntry represents a 64-bit relocation entry with explicit addend (Elf64_Rela).
type RelocationEntry struct {
	Offset uint64 // Address of reference
	Info   uint64 // Symbol index and type of relocation
	Addend int64  // Constant addend
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
// We assume 64-bit for the rest of the header fields as per the project context (ARM64).
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
	Type   uint32 // Segment type
	Flags  uint32 // Segment flags
	Offset uint64 // Segment file offset
	Vaddr  uint64 // Segment virtual address
	Paddr  uint64 // Segment physical address
	Filesz uint64 // Segment file size
	Memsz  uint64 // Segment memory size
	Align  uint64 // Segment alignment
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

	// 1. Read and validate ELF header
	logInfo(cText("* Reading and validating ELF header..."))
	var header ELFHeader
	if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to read ELF header: %w", err)
	}

	if header.Magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return fmt.Errorf("invalid ELF magic number: %x", header.Magic)
	}
	if header.Class != ELFCLASS64 {
		return fmt.Errorf("unsupported ELF class: %d (expected 64-bit)", header.Class)
	}
	if header.Phentsize != 56 { // sizeof(Elf64_Phdr)
		return fmt.Errorf("invalid program header entry size: %d (expected 56)", header.Phentsize)
	}
	logInfo(cSuccess("   -> ELF header validated"), cText("(64-bit, Phentsize "), fValue(header.Phentsize), cText(")"))

	// 2. Read Program Header Table (PHT)
	phtSize := uint64(header.Phnum) * uint64(header.Phentsize)
	if phtSize == 0 || header.Phnum > 1024 { // Sanity check for Phnum
		return fmt.Errorf("invalid number of program headers: %d", header.Phnum)
	}
	logInfo(cText("* Reading PHT at offset "), fAddress(header.PhdrOffset), cText(" e_phnum="), fValue(header.Phnum))

	if _, err := file.Seek(int64(header.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program header table: %w", err)
	}

	phdrs := make([]ProgramHeader, header.Phnum)
	if err := binary.Read(file, binary.LittleEndian, &phdrs); err != nil {
		return fmt.Errorf("failed to read program header table: %w", err)
	}

	// 3. Apply fixes to Program Headers
	logInfo(cText("* Applying fixes to Program Headers..."))
	if err := fixProgramHeaders(file, &header, phdrs, baseAddr); err != nil {
		return fmt.Errorf("program header fix failed: %w", err)
	}
	logInfo(cSuccess("   -> Program Headers fixed successfully."))

	// 4. Fix Dynamic Section
	logInfo(cText("* Fixing Dynamic Section..."))
	if err := fixDynamicSection(file, phdrs, baseAddr); err != nil {
		return fmt.Errorf("dynamic section fix failed: %w", err)
	}
	logInfo(cSuccess("   -> Dynamic Section fixed successfully."))

	// 5. Fix Relocations
	logInfo(cText("* Fixing Relocations..."))
	if err := fixRelocations(file, phdrs, baseAddr); err != nil {
		return fmt.Errorf("relocation fix failed: %w", err)
	}
	logInfo(cSuccess("   -> Relocations fixed successfully."))

	// 6. Rebuild and Write Section Header Table
	logInfo(cText("* Rebuilding and writing Section Header Table (SHT)..."))
	if err := rebuildSectionHeaders(filePath, file, &header, phdrs, baseAddr); err != nil {
		return fmt.Errorf("SHT rebuild failed: %w", err)
	}
	logInfo(cSuccess("   -> SHT rebuilt and written successfully."))

	// 7. Rewrite the fixed PHT back to the file
	if _, err := file.Seek(int64(header.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program header table for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, phdrs); err != nil {
		return fmt.Errorf("failed to write fixed program header table: %w", err)
	}

	// 8. Rewrite the fixed ELF header (in case any fields were modified)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to ELF header for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to write fixed ELF header: %w", err)
	}

	return nil
}

// GNUHashHeader represents the initial part of the DT_GNU_HASH table.
type GNUHashHeader struct {
	Nbuckets  uint32
	Symndx    uint32 // Index of the first symbol in .dynsym that is NOT a local symbol (usually 1)
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
	dynMap := make(map[uint64]uint64)
	for _, entry := range dynamicEntries {
		dynMap[entry.Tag] = entry.Val
	}

	// 2. Collect all necessary section information
	sections := []SectionInfo{
		{Name: "", Type: SHT_NULL, Addralign: 1}, // Null section at index 0
	}
	shstrtab := "\x00" // Section Header String Table starts with null byte
	shNameOffsets := make(map[string]uint32)

	// Helper to add string to shstrtab and return offset
	addShStr := func(name string) uint32 {
		if offset, ok := shNameOffsets[name]; ok {
			return offset
		}
		offset := uint32(len(shstrtab))
		shstrtab += name + "\x00"
		shNameOffsets[name] = offset
		return offset
	}

	// Helper to find the end of the last PT_LOAD segment (file size)
	var maxFileOffset uint64 = 0
	for _, phdr := range phdrs {
		if phdr.Type == PT_LOAD {
			end := phdr.Offset + phdr.Filesz
			if end > maxFileOffset {
				maxFileOffset = end
			}
		}
	}

	// Helper to add a section
	addSection := func(name string, sType uint32, flags uint64, addr, size, align, entsize uint64) {
		if size == 0 && sType != SHT_NULL {
			return // Skip empty sections unless it's the null section
		}
		sections = append(sections, SectionInfo{
			Name:      name,
			Type:      sType,
			Flags:     flags,
			Addr:      addr,
			Offset:    addr, // For dumped SO, offset is usually Vaddr
			Size:      size,
			Addralign: align,
			Entsize:   entsize,
		})
	}

	// 2. Calculate symbol count
	symCount, err := calculateSymbolCount(file, dynMap)
	if err != nil {
		// If calculation fails, fall back to heuristic or return error
		if symCount == 0 {
			return fmt.Errorf("failed to calculate symbol count: %w", err)
		}
	}

	// --- Section Reconstruction Logic ---

	// Add .dynstr
	if dynMap[DT_STRTAB] != 0 && dynMap[DT_STRSZ] != 0 {
		addSection(".dynstr", SHT_STRTAB, SHF_ALLOC, dynMap[DT_STRTAB], dynMap[DT_STRSZ], 1, 0)
	}

	// Add .dynsym
	if dynMap[DT_SYMTAB] != 0 && dynMap[DT_SYMENT] != 0 && symCount > 0 {
		symtabSize := symCount * dynMap[DT_SYMENT]
		addSection(".dynsym", SHT_DYNSYM, SHF_ALLOC, dynMap[DT_SYMTAB], symtabSize, 8, dynMap[DT_SYMENT])
	}

	// Add .gnu.hash
	if dynMap[DT_GNU_HASH] != 0 {
		gnuHashSize, err := calculateGnuHashSize(file, dynMap[DT_GNU_HASH], symCount)
		if err != nil {
			return fmt.Errorf("failed to calculate .gnu.hash size: %w", err)
		}
		addSection(".gnu.hash", SHT_GNU_HASH, SHF_ALLOC, dynMap[DT_GNU_HASH], gnuHashSize, 8, 4)
	}

	// Add .dynamic
	addSection(".dynamic", SHT_DYNAMIC, SHF_ALLOC|SHF_WRITE, dynamicPhdr.Vaddr, dynamicPhdr.Memsz, dynamicPhdr.Align, 16)

	// Add .rela.dyn
	if dynMap[DT_RELA] != 0 && dynMap[DT_RELASZ] != 0 {
		addSection(".rela.dyn", SHT_RELA, SHF_ALLOC, dynMap[DT_RELA], dynMap[DT_RELASZ], 8, 24)
	}

	// Add .rela.plt
	if dynMap[DT_JMPREL] != 0 && dynMap[DT_PLTRELSZ] != 0 {
		addSection(".rela.plt", SHT_RELA, SHF_ALLOC|SHF_INFO_LINK, dynMap[DT_JMPREL], dynMap[DT_PLTRELSZ], 8, 24)
	}

	// Add validation to fixRelocations
	if dynMap[DT_RELAENT] != 0 && dynMap[DT_RELAENT] != 24 {
		return fmt.Errorf("unexpected DT_RELAENT size: %d (expected 24 for ELF64)", dynMap[DT_RELAENT])
	}

	// Add .init_array
	if dynMap[DT_INIT_ARRAY] != 0 && dynMap[DT_INIT_ARRAYSZ] != 0 {
		addSection(".init_array", SHT_INIT_ARRAY, SHF_ALLOC|SHF_WRITE, dynMap[DT_INIT_ARRAY], dynMap[DT_INIT_ARRAYSZ], 8, 8)
	}

	// Add .fini_array
	if dynMap[DT_FINI_ARRAY] != 0 && dynMap[DT_FINI_ARRAYSZ] != 0 {
		addSection(".fini_array", SHT_FINI_ARRAY, SHF_ALLOC|SHF_WRITE, dynMap[DT_FINI_ARRAY], dynMap[DT_FINI_ARRAYSZ], 8, 8)
	}

	// --- Deduce Missing Sections from PHT and Dynamic Pointers ---

	// Find the executable segment (R E) and the writable segment (RW)
	var execPhdr *ProgramHeader
	var rwPhdr *ProgramHeader
	for _, phdr := range phdrs {
		if phdr.Type == PT_LOAD {
			if (phdr.Flags&SHF_EXECINSTR) != 0 && (phdr.Flags&SHF_WRITE) == 0 {
				execPhdr = &phdr
			}
			if (phdr.Flags & SHF_WRITE) != 0 {
				rwPhdr = &phdr
			}
		}
	}

	// Add PT_TLS handling
	var tlsPhdr *ProgramHeader
	for _, phdr := range phdrs {
		if phdr.Type == PT_TLS {
			tlsPhdr = &phdr
			break
		}
	}

	if tlsPhdr != nil && tlsPhdr.Memsz > 0 {
		addSection(".tdata", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, tlsPhdr.Vaddr, tlsPhdr.Filesz, tlsPhdr.Align, 0)
		if tlsPhdr.Memsz > tlsPhdr.Filesz {
			addSection(".tbss", SHT_NOBITS, SHF_ALLOC|SHF_WRITE, tlsPhdr.Vaddr+tlsPhdr.Filesz, tlsPhdr.Memsz-tlsPhdr.Filesz, tlsPhdr.Align, 0)
		}
	}

	// Add PT_NOTE handling
	for i := range phdrs {
		if phdrs[i].Type == PT_NOTE && phdrs[i].Filesz > 0 {
			addSection(".note", SHT_NOTE, SHF_ALLOC, phdrs[i].Vaddr, phdrs[i].Filesz, phdrs[i].Align, 0)
			break
		}
	}

	// Add .plt and .got sections
	if dynMap[DT_PLTGOT] != 0 && dynMap[DT_PLTRELSZ] != 0 {
		pltRelocCount := dynMap[DT_PLTRELSZ] / 24

		// .plt section (executable)
		// Size: 32 bytes (header) + 16 bytes per entry
		pltSize := 32 + (pltRelocCount * 16)
		if execPhdr != nil {
			// Heuristic: place .plt at the start of the executable segment
			pltAddr := execPhdr.Vaddr
			addSection(".plt", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, pltAddr, pltSize, 16, 16)
		}
	}

	// Add symbol versioning sections
	if dynMap[DT_VERSYM] != 0 && symCount > 0 {
		versymSize := symCount * 2 // 2 bytes per symbol
		addSection(".gnu.version", SHT_GNU_VERSYM, SHF_ALLOC, dynMap[DT_VERSYM], versymSize, 2, 2)
	}
	if dynMap[DT_VERNEED] != 0 && dynMap[DT_VERNEEDNUM] > 0 {
		// Size is hard to calculate without parsing the verneed structures.
		// A heuristic: 24 bytes per verneed entry + 16 bytes per vernaux entry.
		// Assume average of 2 aux entries per need.
		verneedSize := dynMap[DT_VERNEEDNUM] * (24 + 2*16)
		addSection(".gnu.version_r", SHT_GNU_VERNEED, SHF_ALLOC, dynMap[DT_VERNEED], verneedSize, 8, 0)
	}

	// Add .eh_frame section from PT_GNU_EH_FRAME
	for i := range phdrs {
		if phdrs[i].Type == PT_GNU_EH_FRAME && phdrs[i].Filesz > 0 {
			// This PHDR covers both .eh_frame_hdr and .eh_frame.
			// We need to find where .eh_frame_hdr ends and .eh_frame begins.
			// The .eh_frame_hdr contains file-relative pointers into .eh_frame.
			// For simplicity, we'll create a single section for now.
			addSection(".eh_frame", SHT_PROGBITS, SHF_ALLOC, phdrs[i].Vaddr, phdrs[i].Filesz, 4, 0)
			break // Assume only one
		}
	}

	// Helper to get all sections currently defined that are file-backed
	getFileBackedSections := func() []SectionInfo {
		fileBacked := make([]SectionInfo, 0)
		for _, sec := range sections {
			if sec.Type != SHT_NULL && sec.Type != SHT_NOBITS {
				fileBacked = append(fileBacked, sec)
			}
		}
		return fileBacked
	}

	// 1. Process Executable Segment (R-E) for .text and .rodata
	if execPhdr != nil {
		// Collect all known file-backed sections that fall within the execPhdr's range
		execSections := make([]SectionInfo, 0)
		for _, sec := range getFileBackedSections() {
			if sec.Addr >= execPhdr.Vaddr && sec.Addr < execPhdr.Vaddr+execPhdr.Filesz {
				execSections = append(execSections, sec)
			}
		}

		// Sort sections by Vaddr to find gaps
		sort.Slice(execSections, func(i, j int) bool {
			return execSections[i].Addr < execSections[j].Addr
		})

		// Find the start of the first known section in the segment
		textRoDataStart := execPhdr.Vaddr
		textRoDataEnd := execPhdr.Vaddr + execPhdr.Filesz // Default to end of segment

		if len(execSections) > 0 {
			textRoDataEnd = execSections[0].Addr
		}

		combinedSize := textRoDataEnd - textRoDataStart

		if combinedSize > 0 {
			// Define a single .text section for the entire combined block (code + read-only data)
			// This is the most robust heuristic when the split point is unknown.
			addSection(".text", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, textRoDataStart, combinedSize, 16, 0)
		}
	}

	// 2. Process Writable Segment (RW) for .data and .bss
	if rwPhdr != nil {
		// Add .got (if not covered by dynamic pointers)
		if dynMap[DT_PLTGOT] != 0 {
			// The .got.plt is part of the .got section, but specifically for PLT entries.
			// The DT_PLTGOT pointer points to the start of the .got section.
			// The first 3 entries are reserved. The rest are for PLT relocations.
			pltRelocCount := dynMap[DT_PLTRELSZ] / 24 // 24 bytes per Elf64_Rela
			gotPltSize := (pltRelocCount + 3) * 8
			addSection(".got.plt", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, dynMap[DT_PLTGOT]+24, gotPltSize, 8, 8)

			// Also add the .got section which contains .got.plt
			// We estimate its size from the start of DT_PLTGOT to the end of the writable segment's file-backed portion.
			if dynMap[DT_PLTGOT] >= rwPhdr.Vaddr {
				gotSize := (rwPhdr.Vaddr + rwPhdr.Filesz) - dynMap[DT_PLTGOT]
				if gotSize > 0 {
					addSection(".got", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, dynMap[DT_PLTGOT], gotSize, 8, 8)
				}
			}
		}

		// Collect all known file-backed sections that fall within the rwPhdr's range
		rwSections := make([]SectionInfo, 0)
		for _, sec := range getFileBackedSections() {
			if sec.Addr >= rwPhdr.Vaddr && sec.Addr < rwPhdr.Vaddr+rwPhdr.Filesz {
				rwSections = append(rwSections, sec)
			}
		}

		// Sort sections by Vaddr to find gaps
		sort.Slice(rwSections, func(i, j int) bool {
			return rwSections[i].Addr < rwSections[j].Addr
		})

		// Find the end of the last known section in the file-backed part.
		var lastKnownEndVaddr uint64 = rwPhdr.Vaddr
		for _, sec := range rwSections {
			endVaddr := sec.Addr + sec.Size
			if endVaddr > lastKnownEndVaddr {
				lastKnownEndVaddr = endVaddr
			}
		}

		// The .data section is the gap between the last known section and the end of the file-backed part.
		dataStart := lastKnownEndVaddr
		dataEnd := rwPhdr.Vaddr + rwPhdr.Filesz
		dataSize := dataEnd - dataStart

		if dataSize > 0 {
			// The .data section is writable and allocated.
			addSection(".data", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, dataStart, dataSize, 16, 0)
		}

		// .bss section (non-file-backed part)
		bssStart := rwPhdr.Vaddr + rwPhdr.Filesz
		bssSize := rwPhdr.Memsz - rwPhdr.Filesz
		if bssSize > 0 {
			addSection(".bss", SHT_NOBITS, SHF_ALLOC|SHF_WRITE, bssStart, bssSize, 16, 0)
		}
	}
	// Add .shstrtab (Section Header String Table)
	shstrtabSectionIndex := uint32(len(sections))
	sections = append(sections, SectionInfo{
		Name:      ".shstrtab",
		Type:      SHT_STRTAB,
		Addralign: 1,
	})

	// 3. Fix Links and Names
	nameToIndex := make(map[string]uint32)
	for i := range sections {
		if sections[i].Name != "" {
			nameToIndex[sections[i].Name] = uint32(i)
			// Add string to shstrtab to populate shNameOffsets map
			addShStr(sections[i].Name)
		}
	}

	// Fix sh_link and sh_info
	dynsymIndex := nameToIndex[".dynsym"]
	dynstrIndex := nameToIndex[".dynstr"]
	pltIndex := nameToIndex[".text"] // Placeholder for .plt, using .text index

	for i := range sections {
		sec := &sections[i]

		switch sec.Name {
		case ".dynsym":
			sec.Link = dynstrIndex
			sec.Info = 1
		case ".gnu.hash":
			sec.Link = dynsymIndex
		case ".dynamic":
			sec.Link = dynstrIndex
		case ".rela.dyn":
			sec.Link = dynsymIndex
		case ".rela.plt":
			sec.Link = dynsymIndex
			sec.Info = pltIndex
		}
	}

	// 4. Finalize .shstrtab section
	shstrtabSection := &sections[shstrtabSectionIndex]
	shstrtabSection.Size = uint64(len(shstrtab))
	shstrtabSection.Offset = maxFileOffset // Place at the end of the file content

	// 5. Build and Write SHT
	shdrTableOffset := shstrtabSection.Offset + shstrtabSection.Size
	shdrTableSize := uint64(len(sections)) * uint64(binary.Size(SectionHeader{}))
	logDebug(cText("   -> Writing SHT at file offset "), fAddress(shdrTableOffset), cText(", size "), cValue(shdrTableSize), cText(", sections "), cValue(len(sections)))

	// Ensure file is large enough for SHT
	if err := os.Truncate(filePath, int64(shdrTableOffset+shdrTableSize)); err != nil {
		return fmt.Errorf("failed to truncate file for SHT: %w", err)
	}

	if _, err := file.Seek(int64(shdrTableOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to SHT offset 0x%x: %w", shdrTableOffset, err)
	}

	// Write SHT
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

	// 6. Write .shstrtab
	if _, err := file.Seek(int64(shstrtabSection.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to .shstrtab offset 0x%x: %w", shstrtabSection.Offset, err)
	}
	if _, err := file.Write([]byte(shstrtab)); err != nil {
		return fmt.Errorf("failed to write .shstrtab: %w", err)
	}

	// 7. Update ELF Header
	header.ShdrOffset = shdrTableOffset
	header.Shentsize = uint16(binary.Size(SectionHeader{}))
	header.Shnum = uint16(len(sections))
	header.Shstrndx = uint16(shstrtabSectionIndex)

	return nil
}

// calculateSymbolCount reads the GNU Hash table and determines the total number of symbols.
func calculateSymbolCount(file *os.File, dynMap map[uint64]uint64) (uint64, error) {
	gnuHashOffset := dynMap[DT_GNU_HASH]
	symtabOffset := dynMap[DT_SYMTAB]
	symEntSize := dynMap[DT_SYMENT]

	if gnuHashOffset == 0 || symtabOffset == 0 || symEntSize == 0 {
		// Fallback to heuristic if GNU hash is missing or incomplete
		if symtabOffset != 0 && dynMap[DT_STRSZ] != 0 {
			return (dynMap[DT_STRSZ] / 10) * symEntSize, nil
		}
		return 0, fmt.Errorf("missing DT_GNU_HASH or DT_SYMTAB/DT_SYMENT")
	}

	// 1. Read GNU Hash Header
	var header GNUHashHeader
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
	// Estimate: typical libraries have < 100k symbols
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

			// Bounds check
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
	// Header (16 bytes) + Bloom Filter + Buckets + Chains
	bloomSize := uint64(header.Maskwords) * 8            // 64-bit bloom filter words
	bucketsSize := uint64(header.Nbuckets) * 4           // 32-bit bucket entries
	chainsSize := (symCount - uint64(header.Symndx)) * 4 // 32-bit chain entries

	totalSize := uint64(16) + bloomSize + bucketsSize + chainsSize
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
	entryCount := dynamicPhdr.Memsz / 16
	dynamicEntries := make([]DynamicEntry, entryCount)
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section for reading: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section for relocation info: %w", err)
	}

	var relaOffset, relaSize, jmprelOffset, jmprelSize uint64;
	for _, entry := range dynamicEntries {
		switch entry.Tag {
		case DT_RELA:
			relaOffset = entry.Val
		case DT_RELASZ:
			relaSize = entry.Val
		case DT_JMPREL:
			jmprelOffset = entry.Val
		case DT_PLTRELSZ:
			jmprelSize = entry.Val
		}
	}
	logDebug(cText("   -> DT_RELA table at "), fAddress(relaOffset), cText(", size="), cValue(relaSize))
	logDebug(cText("   -> DT_JMPREL table at "), fAddress(jmprelOffset), cText(", size="), cValue(jmprelSize))

	// Helper function to process a single relocation table
	processTable := func(offset, size uint64) error {
		if size == 0 {
			return nil
		}
		if size%uint64(binary.Size(RelocationEntry{})) != 0 {
			return fmt.Errorf("relocation table size 0x%x is not a multiple of entry size 0x%x", size, binary.Size(RelocationEntry{}))
		}

		numEntries := size / uint64(binary.Size(RelocationEntry{}))
		relocations := make([]RelocationEntry, numEntries)

		// Read the relocation table
		if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to relocation table at 0x%x: %w", offset, err)
		}
		if err := binary.Read(file, binary.LittleEndian, &relocations); err != nil {
			return fmt.Errorf("failed to read relocation table at 0x%x: %w", offset, err)
		}

		// Fix each relocation entry
		for i := range relocations {
			rel := &relocations[i]
			relType := rel.Info & 0xFFFFFFFF // Lower 32 bits is the type

			// Only fix relocation types that point to absolute addresses in memory.
			if relType == R_AARCH64_RELATIVE || relType == R_AARCH64_GLOB_DAT || relType == R_AARCH64_JUMP_SLOT {
				// The pointer at rel.Offset is a runtime address.
				// We need to read the pointer, subtract the baseAddr, and write it back.

				// 1. Read the pointer value at rel.Offset
				var pointerVal uint64
				if _, err := file.Seek(int64(rel.Offset), io.SeekStart); err != nil {
					return fmt.Errorf("failed to seek to relocation target 0x%x: %w", rel.Offset, err)
				}
				if err := binary.Read(file, binary.LittleEndian, &pointerVal); err != nil {
					return fmt.Errorf("failed to read relocation target at 0x%x: %w", rel.Offset, err)
				}

				// 2. Fix the pointer: pointerVal = pointerVal - baseAddr
				if pointerVal < baseAddr {
					// This should not happen for a runtime address, but check for robustness
					// We will assume it is a runtime address and fix it.
				}
				fixedPointerVal := pointerVal - baseAddr
				logDebug(cText("      - Fixed relocation at "), fAddress(rel.Offset), cText(" to "), fAddress(fixedPointerVal))

				// 3. Write the fixed pointer back
				if _, err := file.Seek(int64(rel.Offset), io.SeekStart); err != nil {
					return fmt.Errorf("failed to seek to relocation target 0x%x for writing: %w", rel.Offset, err)
				}
				if err := binary.Write(file, binary.LittleEndian, fixedPointerVal); err != nil {
					return fmt.Errorf("failed to write fixed relocation target at 0x%x: %w", rel.Offset, err)
				}
			}
		}

		return nil
	}

	// Process DT_RELA and DT_JMPREL tables
	if err := processTable(relaOffset, relaSize); err != nil {
		return fmt.Errorf("DT_RELA fix failed: %w", err)
	}
	if err := processTable(jmprelOffset, jmprelSize); err != nil {
		return fmt.Errorf("DT_JMPREL fix failed: %w", err)
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
		// Not all SOs have a dynamic section (e.g., static linking), so this is not an error.
		return nil
	}

	// Calculate the number of entries. Memsz is the size of the dynamic array.
	entryCount := dynamicPhdr.Memsz / 16 // sizeof(Elf64_Dyn) is 16 bytes

	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero size")
	}
	logDebug(cText("   -> Dynamic segment found p_vaddr="), fAddress(dynamicPhdr.Vaddr), cText(", p_offset="), fAddress(dynamicPhdr.Offset), cText(", entries="), fValue(entryCount))

	// Read the dynamic section content
	dynamicEntries := make([]DynamicEntry, entryCount)

	// Seek to the file offset of the dynamic section
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section: %w", err)
	}

	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section: %w", err)
	}

	// Fix pointers in the dynamic section
	for i := range dynamicEntries {
		entry := &dynamicEntries[i]

		// Only fix entries that are pointers (DT_PTR tags)
		switch entry.Tag {
		case DT_PLTGOT, DT_HASH, DT_GNU_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_VERNEED, DT_VERSYM:
			// Check if the pointer is a runtime address (i.e., greater than the base address)
			if entry.Val >= baseAddr {
				logDebug(cText("      - Fixing dynamic entry "), fValue(entry.Tag), cText(" to "), fAddress(entry.Val-baseAddr))
				entry.Val -= baseAddr
			}
		case DT_PLTRELSZ, DT_RELASZ, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ:
			// Size tags are values, not pointers, so no conversion needed.
		case DT_NULL:
			// End of dynamic section, stop processing.
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
	// The baseAddr is the runtime address where the SO was loaded.
	// We use it to determine if the Vaddr is a runtime address or a relative address.
	// A typical relative Vaddr is small (e.g., < 0x1000000).

	isRuntimeAddr := func(addr uint64) bool {
		// If the address is larger than a typical relative offset (e.g., 1GB),
		// it's probably a runtime address.
		return addr > 0x100000000
	}

	// 1. Determine if the file contains runtime addresses.
	// We check the first PT_LOAD segment's Vaddr.
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

	// 2. Apply fixes
	for i := range phdrs {
		phdr := &phdrs[i]

		if phdr.Type == PT_LOAD {
			// Normalization: For a memory dump, the file size is often the memory size.
			phdr.Filesz = phdr.Memsz
			phdr.Paddr = phdr.Vaddr
			phdr.Offset = phdr.Vaddr

			if needsConversion {
				// Convert runtime Vaddr to file-relative Vaddr
				if phdr.Vaddr < baseAddr {
					return fmt.Errorf("PT_LOAD segment Vaddr 0x%x is less than base address 0x%x", phdr.Vaddr, baseAddr)
				}
				relativeVaddr := phdr.Vaddr - baseAddr

				// Apply the relative Vaddr to all address/offset fields
				phdr.Offset = relativeVaddr
				phdr.Vaddr = relativeVaddr
				phdr.Paddr = relativeVaddr
			} else {
				// If already relative, ensure Offset/Vaddr/Paddr consistency for normalization
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
		}

		// Fix PT_PHDR: it points to the PHT itself.
		if phdr.Type == PT_PHDR {
			// The PHT is at header.PhdrOffset in the file.
			// The Vaddr/Paddr/Offset should all point to the file offset.
			phdr.Vaddr = header.PhdrOffset
			phdr.Paddr = header.PhdrOffset
			phdr.Offset = header.PhdrOffset
		}

		// Fix GNU-specific headers: PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK
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
				// If already relative, ensure Offset/Paddr consistency
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
			// Also ensure Filesz = Memsz for consistency, especially for PT_GNU_RELRO
			if phdr.Type == PT_GNU_RELRO {
				phdr.Filesz = phdr.Memsz
			}
		}

		// Fix PT_DYNAMIC: it points to the dynamic section.
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
				// If already relative, ensure Offset/Paddr consistency
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
		}
	}

	// Update ELF header fields to reflect the fixed PHT
	header.Type = ET_DYN
	header.Machine = EM_AARCH64

	return nil
}
