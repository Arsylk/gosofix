package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
)

var (
	debugEnabled bool
	// Color functions for different elements (Base16 Catppuccin Mocha inspired)
	cPrefix  = color.New(color.FgHiCyan).SprintFunc()  // Mauve
	cText    = color.New(color.FgWhite).SprintFunc()   // Text
	cValue   = color.New(color.FgHiGreen).SprintFunc() // Green
	fValue   = func(value interface{}) string { return cValue(fmt.Sprintf("%d", value)) }
	cAddress = color.New(color.FgHiMagenta).SprintFunc() // Blue
	fAddress = func(addr uint64) string { return cAddress(fmt.Sprintf("0x%x", addr)) }
	cLabel   = color.New(color.FgHiBlue).SprintFunc()               // Blue
	cPath    = color.New(color.FgHiYellow).SprintFunc()             // Yellow
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
	File      *os.File
	ElfHeader *Elf64_Ehdr
	Phdrs     []Elf64_Phdr
	Dyns      []Elf64_Dyn
	Sections  *[]Elf64_Shdr
	Rel       []Elf64_Rel
	Rela      []Elf64_Rela
	JmpRel    []Elf64_Rel
	JmpRela   []Elf64_Rela
	Symbols   []Elf64_Sym

	dynMap              map[DT_Tag]uint64
	strtabOffset        uint64
	symtabOffset        uint64
	relOffset           uint64
	relSize             uint64
	relaOffset          uint64
	relaSize            uint64
	jmprelOffset        uint64
	jmprelSize          uint64
	jmprelEntry         uint64
	phdrPtLoadPageStart uint64
	symCount            uint64

	newStrtabMap map[string]uint32
	newStrtab    []byte
	newSymbols   []Elf64_Sym
}

const (
	ELFCLASS32 = 1
	ELFCLASS64 = 2

	ET_DYN     = 3
	EM_AARCH64 = 183

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

// Elf64_Shdr represents a 64-bit section header entry (Elf64_Shdr).
type Elf64_Shdr struct {
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

type Elf64_Sym struct {
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
func FixELFHeaders(filePath string, baseAddr uint64, outputPath string, debug bool) error {
	debugEnabled = debug
	logInfo(cText("Starting ELF fix for file: "), cPath(filePath), cText(" at base address "), fAddress(baseAddr))

	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var reader ElfReader = ElfReader{
		File:      file,
		ElfHeader: new(Elf64_Ehdr),
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

	// 6. Build Strtab & Symtab
	if err := reader.BuildStrtab(); err != nil {
		return err
	}

	// 7. Write new ELF
	if err := reader.WriteFixedElf(outputPath, baseAddr); err != nil {
		return err
	}
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

	r.Phdrs = make([]Elf64_Phdr, r.ElfHeader.Phnum)
	if err := binary.Read(r.File, binary.LittleEndian, r.Phdrs); err != nil {
		return fmt.Errorf("failed to read program header table: %w", err)
	}

	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && r.phdrPtLoadPageStart == 0 {
			r.phdrPtLoadPageStart = PageStart(phdr.Vaddr)
		}
		logDebug(cText("  + "), cValue(phdr.Type.Text()), cText(" at "), fAddress(phdr.Offset))
	}

	return nil
}

func (r *ElfReader) ReadDyns() error {
	var dynamicPhdr *Elf64_Phdr
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
	r.Dyns = make([]Elf64_Dyn, entryCount)

	// For memory dumps, use p_vaddr as the file offset since the dump is sequential by VA
	// For regular ELF files, p_offset would be correct, but memory dumps don't follow that
	dynamicOffset := dynamicPhdr.Vaddr
	logDebug(cText("   -> Using vaddr as file offset: "), fAddress(dynamicOffset))

	if _, err := r.File.Seek(int64(dynamicOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section: %w", err)
	}

	if err := binary.Read(r.File, binary.LittleEndian, r.Dyns); err != nil {
		return fmt.Errorf("failed to read dynamic section: %w", err)
	}

	r.dynMap = make(map[DT_Tag]uint64)
	for _, entry := range r.Dyns {
		baseLog := fValue(entry.Val)
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
				r.jmprelEntry = uint64(binary.Size(Elf64_Rel{}))
			} else {
				r.jmprelEntry = uint64(binary.Size(Elf64_Rela{}))
			}
		case DT_PLTRELSZ:
			r.jmprelSize = entry.Val
		}
		logInfo(cText("    - dynamic "), cLabel(entry.Tag.Text()), cText(" "), baseLog)
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
	r.Symbols = make([]Elf64_Sym, r.symCount)
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
		r.Rel = make([]Elf64_Rel, relCount)
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
		r.Rela = make([]Elf64_Rela, relaCount)
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
			r.JmpRel = make([]Elf64_Rel, jmprelCount)
			if _, err = r.File.Seek(int64(r.jmprelOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to jmprel table: %w", err)
			}
			if err = binary.Read(r.File, binary.LittleEndian, r.JmpRel); err != nil {
				return fmt.Errorf("failed to read jmprel table: %w", err)
			}
		} else {
			jmprelCount := r.jmprelSize / 24
			logInfo(cText(" + DT_JMPREL at "), fAddress(r.jmprelOffset), cText(" count="), fValue(jmprelCount))
			r.JmpRela = make([]Elf64_Rela, jmprelCount)
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
	// --- Base Address is forced to 0 for this calculation ---
	base = 0

	// Calculate Load Bias: B = base - r.phdrPtLoadPageStart
	// If base is 0, the loadBias becomes -r.phdrPtLoadPageStart.
	// For position-independent executables (PIEs) where r.phdrPtLoadPageStart is typically 0,
	// loadBias will be 0, simplifying the RELATIVE formula.
	// loadBias := base - r.phdrPtLoadPageStart

	// --- Helper function for Rel (Relocation without Addend) ---
	fnRel := func(rel *Elf64_Rel) {
		relocType := rel.Type()
		relocSym := rel.Sym()
		rsym := r.Symbols[relocSym]
		rname := readStrtabString(r.File, r.strtabOffset, rsym.St_Name)

		// L: Location (Address of the relocation site in memory, treating base as 0)
		// L := base + rel.Offset
		// S: Symbol Value (runtime address, which is now the intended virtual address)
		S := rsym.St_Value

		// P: Final calculated value (intended VA)
		var P uint64

		switch relocType {
		case R_AARCH64_NONE:
			P = 0

		case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT:
			// P = S + A (A=0) => P = S
			// The entry points/global data pointers are set to the symbol's intended VA.
			P = S

		case R_AARCH64_ABS64, R_AARCH64_ABS32:
			// P = S + A (A is original value at L)
			// Assuming A=0 for this Rel handler.
			P = S

		default:
			P = S
		}

		rel.Offset = P
		logDebug(cText("    - rel "), cLabel(relocType.Text()), cText(" "), cValue(rname), cText(" final VA "), fAddress(P))
	}

	// --- Helper function for Rela (Relocation with Explicit Addend) ---
	fnRela := func(rela *Elf64_Rela) {
		relocType := rela.Type()
		relocSym := rela.Sym()
		rsym := r.Symbols[relocSym]
		rname := readStrtabString(r.File, r.strtabOffset, rsym.St_Name)

		// L: Location (Address of the relocation site in memory, treating base as 0)
		L := base + rela.Offset

		// A: Addend (explicit in Rela)
		A := uint64(rela.Addend)

		// S: Symbol Value (intended virtual address of the symbol)
		S := rsym.St_Value

		// P: Final calculated value (intended VA)
		var P uint64

		switch relocType {
		case R_AARCH64_NONE:
			P = A

		case R_AARCH64_RELATIVE:
			// P = B + A
			// Since B (loadBias) is now 0, P = 0 + A.
			// The original value (Addend A) is the intended virtual offset.
			P = A // P = A

		case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT:
			// P = S + A
			// The entry points/global data pointers are set to the symbol's intended VA + Addend.
			P = S + A

		case R_AARCH64_ABS64, R_AARCH64_ABS32:
			// P = S + A
			P = S + A

		case R_AARCH64_PREL64, R_AARCH64_PREL32:
			// P = S + A - L
			// This calculates the difference between the target VA and the relocation site VA.
			P = S + A - L

		default:
			P = S + A
		}

		// Store the calculated intended Virtual Address (VA) in the Offset field.
		rela.Offset = P
		logDebug(cText("    - rela "), cLabel(relocType.Text()), cText(" "), cValue(rname), cText(" final VA "), fAddress(P))

	}

	// --- Execute Relocations ---
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

// BuildStrtab builds a new string table with all symbol names
func (r *ElfReader) BuildStrtab() error {
	logInfo(cText("* Building new string table..."))

	if len(r.Symbols) == 0 {
		logInfo(cWarning("   -> No symbols to process, skipping string table build"))
		r.newStrtab = []byte{0}
		r.newStrtabMap = make(map[string]uint32)
		r.newSymbols = []Elf64_Sym{{}} // Just null symbol
		return nil
	}

	r.newStrtabMap = make(map[string]uint32)
	r.newStrtab = []byte{0} // Start with null byte
	r.newSymbols = make([]Elf64_Sym, 0, len(r.Symbols))

	// Helper to add string to new strtab
	addString := func(s string) uint32 {
		if s == "" {
			return 0
		}
		if offset, ok := r.newStrtabMap[s]; ok {
			return offset
		}
		offset := uint32(len(r.newStrtab))
		r.newStrtab = append(r.newStrtab, []byte(s)...)
		r.newStrtab = append(r.newStrtab, 0)
		r.newStrtabMap[s] = offset
		return offset
	}

	// Add null symbol
	r.newSymbols = append(r.newSymbols, Elf64_Sym{})

	// Process all symbols
	localSymbols := []Elf64_Sym{}
	globalSymbols := []Elf64_Sym{}

	for i, sym := range r.Symbols {
		if sym.St_Name == 0 && sym.St_Value == 0 && sym.St_Size == 0 && i != 0 {
			continue // Skip null entries (but not the first one)
		}

		// Read original symbol name
		symName := readStrtabString(r.File, r.strtabOffset, sym.St_Name)

		logDebug(cText("      - Symbol["), fValue(i), cText("]: "), cValue(symName),
			cText(" value="), fAddress(sym.St_Value),
			cText(" "), cLabel(sym.stBind().Text()))

		// Update name offset in new strtab
		sym.St_Name = addString(symName)

		// Separate local and global symbols (ELF requires locals first)
		if sym.stBind() == STB_LOCAL {
			localSymbols = append(localSymbols, sym)
		} else {
			globalSymbols = append(globalSymbols, sym)
		}
	}

	// Add local symbols first, then global
	r.newSymbols = append(r.newSymbols, localSymbols...)
	r.newSymbols = append(r.newSymbols, globalSymbols...)

	logInfo(cText("   -> Built string table: "), fValue(len(r.newStrtab)), cText(" bytes, "),
		fValue(len(r.newSymbols)), cText(" symbols ("),
		fValue(len(localSymbols)), cText(" local, "),
		fValue(len(globalSymbols)), cText(" global)"))

	return nil
}

// WriteFixedElf writes a new properly structured ELF file
func (r *ElfReader) WriteFixedElf(outputPath string, baseAddr uint64) error {
	file, err := os.OpenFile(outputPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	rebuilder := NewElfRebuilder(r)
	if err := rebuilder.writeRelocations(file); err != nil {
		return err
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

func readStrtabString(file *os.File, strtabOffset uint64, nameOffset uint32) string {
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
