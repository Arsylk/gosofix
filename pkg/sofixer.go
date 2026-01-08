package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

var (
	// Logger instance with custom styles
	logger *log.Logger
)

func init() {
	// Create custom styles for the logger - minimalist machine-like format
	styles := log.DefaultStyles()

	// Symbolic prefixes with strict color coding
	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().
		SetString("[?]").
		Foreground(lipgloss.Color("243")) // grey - trace/debug
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().
		SetString("[+]").
		Foreground(lipgloss.Color("86")) // cyan - success/info
	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().
		SetString("[!]").
		Foreground(lipgloss.Color("221")) // yellow - warning
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("[x]").
		Foreground(lipgloss.Color("#f38ba8")) // red - error

	// Style for keys and values
	styles.Key = lipgloss.NewStyle().Foreground(lipgloss.Color("#585b70"))
	styles.Value = lipgloss.NewStyle().Foreground(lipgloss.Color("#b4befe"))

	// Address values get orange highlight
	for _, key := range []string{"vaddr", "addr", "offset", "base", "from", "to", "end", "final_va", "range1", "range2"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#fab387")).Transform(func(s string) string {
			if num, err := strconv.Atoi(s); err == nil {
				return fmt.Sprintf("0x%x", num)
			}
			return s
		})
	}
	// Type tags get blue bold
	for _, key := range []string{"type", "tag", "reloc", "bind"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa")).Bold(true)
	}
	// File paths get yellow
	for _, key := range []string{"file", "path"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#f9e2af"))
	}
	// Names get green
	for _, key := range []string{"name", "sym", "lib", "section", "section1", "section2"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1"))
	}

	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: false,
		ReportCaller:    false,
	})
	logger.SetStyles(styles)
}

type ElfReader struct {
	File      *os.File
	ElfHeader *Elf64_Ehdr
	Phdrs     []Elf64_Phdr
	Dyns      []Elf64_Dyn
	Sections  []Elf64_Shdr
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

	// .got, .init_array, .fini_array
	gotOffset       uint64
	gotSize         uint64
	initArrayOffset uint64
	initArraySize   uint64
	finiArrayOffset uint64
	finiArraySize   uint64

	// .init, .fini functions (single pointers, not arrays)
	initFunc uint64
	finiFunc uint64

	// .preinit_array
	preinitArrayOffset uint64
	preinitArraySize   uint64

	// .hash and .gnu.hash
	hashOffset    uint64
	hashSize      uint64
	gnuHashOffset uint64
	gnuHashSize   uint64

	// .dynamic section
	dynamicOffset uint64
	dynamicSize   uint64

	// PT_GNU_RELRO

	// PT_GNU_EH_FRAME (.eh_frame_hdr)
	ehFrameHdrOffset uint64
	ehFrameHdrSize   uint64

	// .eh_frame section (exception handling frame info)
	ehFrameOffset uint64
	ehFrameSize   uint64

	// PT_NOTE (.note.gnu.build-id)
	noteOffset uint64
	noteSize   uint64

	// .plt section info (calculated)
	pltAddr uint64
	pltSize uint64

	// .text section info (calculated)
	textAddr uint64
	textSize uint64

	// .data and .bss sections (calculated)
	computedSections []ComputedSection

	// Versioning information
	verneedOffset uint64
	verneedNum    uint16
	versymOffset  uint64

	// Dependencies
	neededLibs []string
	soname     string
	runpath    string
	flags      uint64
	flags1     uint64

	// Specialized segments
	tlsOffset uint64
	tlsSize   uint64
	relroAddr uint64
	relroSize uint64

	// .strtab size
	strtabSize uint64

	newStrtabMap map[string]uint32
	newStrtab    []byte
	newSymbols   []Elf64_Sym

	dtRelCount  uint64
	dtRelaCount uint64

	NoteSegments []AddrRange

	BaseAddr uint64
}

const (
	ELFCLASS32 = 1
	ELFCLASS64 = 2

	ET_DYN     = 3
	EM_AARCH64 = 183

	SHF_WRITE     = 0x1
	SHF_ALLOC     = 0x2
	SHF_EXECINSTR = 0x4
	SHF_INFO_LINK = 0x40

	ARM64_PLT0_SIZE      = 32
	ARM64_PLT_ENTRY_SIZE = 16
)

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

// alignUp rounds up 'value' to the next multiple of 'align'
func alignUp(value, align uint64) uint64 {
	if align == 0 {
		return value
	}
	return (value + align - 1) & ^(align - 1)
}

// FixELFHeaders attempts to fix common issues with ELF headers.
func FixELFHeaders(filePath string, baseAddr uint64, outputPath string, debug bool, verbose bool) error {
	if debug {
		logger.SetLevel(log.DebugLevel)
	} else if verbose {
		logger.SetLevel(log.InfoLevel)
	} else {
		logger.SetLevel(log.WarnLevel)
	}
	logger.Info("elf:fix", "file", filePath, "base", baseAddr)

	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var reader ElfReader = ElfReader{
		File:      file,
		ElfHeader: new(Elf64_Ehdr),
		BaseAddr:  baseAddr,
	}

	// 1. Read and validate ELF header
	if err := reader.ReadElfHeaders(); err != nil {
		return fmt.Errorf("failed to read ELF headers: %w", err)
	}

	// 2. Read Program Header Table (PHT)
	if err := reader.ReadPhdrs(); err != nil {
		return fmt.Errorf("failed to read program headers: %w", err)
	}

	// 3. Read Dynamic Section (DT)
	if err := reader.ReadDyns(); err != nil {
		return fmt.Errorf("failed to read dynamic section: %w", err)
	}

	// 4. Read Relocations (REL/RELA)
	if err := reader.ReadRelocs(); err != nil {
		return fmt.Errorf("failed to read relocations: %w", err)
	}

	// 5. Fix Relocs
	if err := reader.FixRelocs(baseAddr); err != nil {
		return fmt.Errorf("failed to fix relocations: %w", err)
	}

	// 6. Build Strtab & Symtab
	if err := reader.BuildStrtab(); err != nil {
		return fmt.Errorf("failed to build string/symbol tables: %w", err)
	}

	// 7. Write new ELF
	if err := reader.WriteFixedElf(outputPath, baseAddr); err != nil {
		return fmt.Errorf("failed to write fixed ELF: %w", err)
	}
	return nil
}

func (r *ElfReader) ReadElfHeaders() error {
	logger.Info("elf:header | reading")
	if err := binary.Read(r.File, binary.LittleEndian, r.ElfHeader); err != nil {
		return fmt.Errorf("failed to read ELF header: %w", err)
	}
	if r.ElfHeader.Magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return fmt.Errorf("invalid ELF magic number: %x (expected 0x7f454c46)", r.ElfHeader.Magic)
	}
	if r.ElfHeader.Class != ELFCLASS64 {
		return fmt.Errorf("unsupported ELF class: %d (expected 64-bit/2)", r.ElfHeader.Class)
	}
	if r.ElfHeader.Machine != EM_AARCH64 {
		return fmt.Errorf("unsupported architecture: %d (expected AArch64/183)", r.ElfHeader.Machine)
	}
	if r.ElfHeader.Phentsize != 56 {
		return fmt.Errorf("invalid program header entry size: %d (expected 56)", r.ElfHeader.Phentsize)
	}
	if r.ElfHeader.Type != ET_DYN {
		return fmt.Errorf("unsupported ELF type: %d (expected shared object/3)", r.ElfHeader.Type)
	}
	logger.Info("elf:header | valid", "class", "64-bit", "arch", "aarch64", "type", "shared object", "phentsize", r.ElfHeader.Phentsize)

	return nil
}

func (r *ElfReader) ReadPhdrs() error {
	phtSize := uint64(r.ElfHeader.Phnum) * uint64(r.ElfHeader.Phentsize)
	if phtSize == 0 {
		return fmt.Errorf("phdr:read | no program headers found")
	}
	if r.ElfHeader.Phnum > 1024 {
		return fmt.Errorf("phdr:read | too many headers: %d (max 1024)", r.ElfHeader.Phnum)
	}

	logger.Info("phdr:read", "offset", fmt.Sprintf("0x%x", r.ElfHeader.PhdrOffset), "count", r.ElfHeader.Phnum)

	var err error
	if r.Phdrs, err = readArray[Elf64_Phdr](r.File, r.ElfHeader.PhdrOffset, uint64(r.ElfHeader.Phnum), "PT_PHDR"); err != nil {
		return err
	}

	for i := range r.Phdrs {
		phdr := &r.Phdrs[i]

		// Normalize Vaddr if it appears absolute
		if r.BaseAddr != 0 && phdr.Vaddr >= r.BaseAddr {
			phdr.Vaddr -= r.BaseAddr
		}

		// Log all program headers with consistent format
		logger.Debug("phdr:entry",
			"idx", i,
			"type", phdr.Type.Text(),
			"vaddr", fmt.Sprintf("0x%x", phdr.Vaddr),
			"filesz", phdr.Filesz,
			"memsz", phdr.Memsz,
			"flags", fmt.Sprintf("0x%x", phdr.Flags),
		)
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

	if dynamicPhdr == nil {
		logger.Warn("dyn:missing")
		return nil
	}

	entryCount := dynamicPhdr.Memsz / uint64(binary.Size(Elf64_Dyn{}))
	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero entries")
	}

	logger.Info("dyn:read", "vaddr", fmt.Sprintf("0x%x", dynamicPhdr.Vaddr), "entries", entryCount)

	// Store dynamic section info for rebuilder
	r.dynamicOffset = dynamicPhdr.Vaddr
	r.dynamicSize = dynamicPhdr.Memsz

	// Read the dynamic section content
	var err error
	if r.Dyns, err = readArray[Elf64_Dyn](r.File, r.dynamicOffset, entryCount, "DT_DYNAMIC"); err != nil {
		return err
	}

	// Build map and extract essential fields for rebuilder
	r.dynMap = make(map[DT_Tag]uint64)
	for _, entry := range r.Dyns {
		val := entry.Val

		// Normalize addresses relative to base
		switch entry.Tag {
		case DT_STRTAB, DT_SYMTAB, DT_REL, DT_RELA, DT_JMPREL, DT_HASH, DT_GNU_HASH, DT_INIT_ARRAY, DT_FINI_ARRAY:
			if val >= r.BaseAddr {
				val -= r.BaseAddr
				logger.Debug("dyn:normalize", "tag", entry.Tag.Text(), "val", fmt.Sprintf("0x%x", val))
			}
		}

		// Only extract fields actually used by the rebuilder
		switch entry.Tag {
		case DT_STRTAB:
			r.strtabOffset = val
		case DT_SYMTAB:
			r.symtabOffset = val
		case DT_HASH:
			r.hashOffset = val
		case DT_GNU_HASH:
			r.gnuHashOffset = val
		case DT_REL:
			r.relOffset = val
		case DT_RELSZ:
			r.relSize = val
		case DT_RELA:
			r.relaOffset = val
		case DT_RELASZ:
			r.relaSize = val
		case DT_JMPREL:
			r.jmprelOffset = val
		case DT_PLTREL:
			if val == uint64(DT_REL) {
				r.jmprelEntry = uint64(binary.Size(Elf64_Rel{}))
			} else {
				r.jmprelEntry = uint64(binary.Size(Elf64_Rela{}))
			}
		case DT_PLTRELSZ:
			r.jmprelSize = val
		case DT_INIT_ARRAY:
			r.initArrayOffset = val
		case DT_INIT_ARRAYSZ:
			r.initArraySize = val
		case DT_FINI_ARRAY:
			r.finiArrayOffset = val
		case DT_FINI_ARRAYSZ:
			r.finiArraySize = val
		}

		logger.Debug("dyn:entry", "tag", entry.Tag.Text(), "val", fmt.Sprintf("0x%x", val))
		r.dynMap[entry.Tag] = val
	}

	return nil
}

func (r *ElfReader) ReadRelocs() error {
	if err := r.readSymbols(); err != nil {
		return err
	}

	if err := r.readRelocationTables(); err != nil {
		return err
	}

	// Simplified: only resolve metadata for logging
	// The complex section analysis (calculateTextSection, analyzeDataSections, etc.)
	// is no longer needed as the rebuilder now uses segment-based sections directly.
	r.ResolveMetadata()

	return nil
}

// readSymbols reads the symbol table
func (r *ElfReader) readSymbols() error {
	var err error
	if r.symCount, err = r.calculateSymbolCount(); err != nil {
		return fmt.Errorf("sym:read | %w", err)
	}

	if r.symCount == 0 {
		logger.Warn("sym:none")
		return nil
	}

	logger.Info("sym:count", "count", r.symCount)
	if r.Symbols, err = readArray[Elf64_Sym](r.File, r.symtabOffset, r.symCount, "DT_SYMTAB"); err != nil {
		return fmt.Errorf("failed to read symbols: %w", err)
	}

	return nil
}

// readRelocationTables reads all relocation tables (REL, RELA, JMPREL)
func (r *ElfReader) readRelocationTables() error {
	var err error

	if r.relOffset != 0 {
		relCount := r.relSize / uint64(binary.Size(Elf64_Rel{}))
		logger.Info("rel:read", "offset", r.relOffset, "count", relCount)
		if r.Rel, err = readArray[Elf64_Rel](r.File, r.relOffset, relCount, "DT_REL"); err != nil {
			return err
		}
	}

	if r.relaOffset != 0 {
		relaCount := r.relaSize / uint64(binary.Size(Elf64_Rela{}))
		logger.Info("rela:read", "offset", r.relaOffset, "count", relaCount)
		if r.Rela, err = readArray[Elf64_Rela](r.File, r.relaOffset, relaCount, "DT_RELA"); err != nil {
			return err
		}
	}

	if r.jmprelOffset != 0 {
		if r.jmprelEntry == 16 {
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rel{}))
			logger.Info("jmprel:read", "offset", r.jmprelOffset, "count", jmprelCount, "type", "REL")
			if r.JmpRel, err = readArray[Elf64_Rel](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
		} else {
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rela{}))
			logger.Info("jmprel:read", "offset", r.jmprelOffset, "count", jmprelCount, "type", "RELA")
			if r.JmpRela, err = readArray[Elf64_Rela](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *ElfReader) FixRelocs(base uint64) error {
	logger.Info("reloc:fix", "base", base)

	r.fixRelArray(r.Rel, base)
	r.fixRelaArray(r.Rela, base)
	r.fixRelArray(r.JmpRel, base)
	r.fixRelaArray(r.JmpRela, base)

	logger.Info("reloc:done", "rel", len(r.Rel), "rela", len(r.Rela), "jmprel", len(r.JmpRel), "jmprela", len(r.JmpRela))
	return nil
}

// fixRelArray processes an array of REL relocations
func (r *ElfReader) fixRelArray(relocs []Elf64_Rel, base uint64) {
	for i := range relocs {
		r.fixSingleRel(&relocs[i], base)
	}
}

// fixRelaArray processes an array of RELA relocations
func (r *ElfReader) fixRelaArray(relocs []Elf64_Rela, base uint64) {
	for i := range relocs {
		r.fixSingleRela(&relocs[i], base)
	}
}

// fixSingleRel fixes a single REL relocation entry
func (r *ElfReader) fixSingleRel(rel *Elf64_Rel, base uint64) {
	relocType := rel.Type()
	relocSym := rel.Sym()
	rsym := r.Symbols[relocSym]
	rname := r.readStrtabString(rsym.St_Name)

	L := base + rel.Offset // Location in memory
	S := rsym.St_Value     // Symbol value

	var P uint64
	switch relocType {
	case R_AARCH64_NONE:
		P = 0
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT:
		P = S // Entry points set to symbol VA
	case R_AARCH64_ABS64, R_AARCH64_ABS32:
		P = S // Absolute references
	case R_AARCH64_RELATIVE:
		P = L // Relative to base + offset
	default:
		P = S // Default to symbol value
	}

	rel.Offset = P
	logger.Debug("rel:fixed", "type", relocType.Text(), "sym", rname, "final_va", P)
}

// fixSingleRela fixes a single RELA relocation entry
func (r *ElfReader) fixSingleRela(rela *Elf64_Rela, base uint64) {
	relocType := rela.Type()
	relocSym := rela.Sym()
	rsym := r.Symbols[relocSym]
	rname := r.readStrtabString(rsym.St_Name)

	L := base + rela.Offset  // Location in memory
	A := uint64(rela.Addend) // Addend
	S := rsym.St_Value       // Symbol value

	var P uint64
	switch relocType {
	case R_AARCH64_NONE:
		P = A
	case R_AARCH64_RELATIVE:
		P = A // Base relative with addend
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT:
		P = S + A // Symbol + addend
	case R_AARCH64_ABS64, R_AARCH64_ABS32:
		P = S + A // Absolute + addend
	case R_AARCH64_PREL64, R_AARCH64_PREL32:
		P = S + A - L // PC-relative
	default:
		P = S + A // Default symbol + addend
	}

	rela.Offset = P
	logger.Debug("rela:fixed", "type", relocType.Text(), "sym", rname, "final_va", P)
}

// BuildStrtab builds a new string table with all symbol names
func (r *ElfReader) BuildStrtab() error {
	logger.Info("strtab:build")

	if len(r.Symbols) == 0 {
		return r.buildEmptyStrtab()
	}

	return r.buildPopulatedStrtab()
}

// buildEmptyStrtab handles the case with no symbols
func (r *ElfReader) buildEmptyStrtab() error {
	logger.Warn("strtab:empty | minimal")
	r.newStrtab = []byte{0}
	r.newStrtabMap = make(map[string]uint32)
	r.newSymbols = []Elf64_Sym{{}} // Just null symbol
	return nil
}

// buildPopulatedStrtab builds string table for files with symbols
func (r *ElfReader) buildPopulatedStrtab() error {
	r.newStrtabMap = make(map[string]uint32)
	r.newStrtab = []byte{0} // Start with null byte
	r.newSymbols = make([]Elf64_Sym, 0, len(r.Symbols))

	// Add null symbol
	r.newSymbols = append(r.newSymbols, Elf64_Sym{})

	// Add library names (DT_NEEDED, DT_SONAME, DT_RUNPATH) to strtab
	for _, lib := range r.neededLibs {
		r.addStringToStrtab(lib)
	}
	if r.soname != "" {
		r.addStringToStrtab(r.soname)
	}
	if r.runpath != "" {
		r.addStringToStrtab(r.runpath)
	}

	// Process all symbols
	localSymbols, globalSymbols := r.processSymbols()

	// Add local symbols first, then global (ELF requirement)
	r.newSymbols = append(r.newSymbols, localSymbols...)
	r.newSymbols = append(r.newSymbols, globalSymbols...)

	logger.Info("strtab:done", "size", len(r.newStrtab), "null", 1, "local", len(localSymbols), "global", len(globalSymbols), "libs", len(r.neededLibs))
	return nil
}

// processSymbols reads and categorizes all symbols
func (r *ElfReader) processSymbols() ([]Elf64_Sym, []Elf64_Sym) {
	localSymbols := []Elf64_Sym{}
	globalSymbols := []Elf64_Sym{}

	for i, sym := range r.Symbols {
		// Skip the first symbol (null symbol)
		if i == 0 {
			continue
		}

		// Skip empty/null entries
		if sym.IsEmptySymbol() {
			continue
		}

		// Read original symbol name
		symName := r.readStrtabString(sym.St_Name)
		logger.Debug("sym:process", "idx", i, "name", symName, "value", sym.St_Value, "bind", sym.stBind().Text(), "type", sym.stType())

		// Update name offset in new strtab
		sym.St_Name = r.addStringToStrtab(symName)

		// Categorize by binding (ELF requires locals first)
		if sym.stBind() == STB_LOCAL {
			localSymbols = append(localSymbols, sym)
		} else {
			globalSymbols = append(globalSymbols, sym)
		}
	}

	return localSymbols, globalSymbols
}

// addStringToStrtab adds a string to the new string table and returns its offset
func (r *ElfReader) addStringToStrtab(s string) uint32 {
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

// calculateSymbolCount determines the total number of symbols using hash tables
func (r *ElfReader) calculateSymbolCount() (uint64, error) {
	// Try .hash table first (simpler, direct symbol count)
	if r.hashOffset != 0 {
		logger.Info("sym:count | via hash")

		if _, err := r.File.Seek(int64(r.hashOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("hash:seek | %w", err)
		}

		var header HashHeader
		if err := binary.Read(r.File, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("hash:read | %w", err)
		}

		return uint64(header.Nchain), nil
	}

	// Fall back to .gnu.hash table
	if r.gnuHashOffset != 0 {
		logger.Info("sym:count | via gnu_hash")

		if _, err := r.File.Seek(int64(r.gnuHashOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("gnu_hash:seek | %w", err)
		}

		var header GNUHashHeader
		if err := binary.Read(r.File, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("gnu_hash:read | %w", err)
		}

		// Calculate bucket and chain offsets
		bloomSize := header.Maskwords * 8
		bucketsOffset := r.gnuHashOffset + 16 + uint64(bloomSize)
		chainsOffset := bucketsOffset + uint64(header.Nbuckets*4)

		// Read buckets to find max symbol index
		buckets := make([]uint32, header.Nbuckets)
		if _, err := r.File.Seek(int64(bucketsOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("gnu_hash:buckets_seek | %w", err)
		}
		if err := binary.Read(r.File, binary.LittleEndian, &buckets); err != nil {
			return 0, fmt.Errorf("gnu_hash:buckets_read | %w", err)
		}

		// Find max bucket index
		maxBucketIndex := uint32(0)
		for _, bptr := range buckets {
			if bptr > maxBucketIndex {
				maxBucketIndex = bptr
			}
		}

		if maxBucketIndex == 0 {
			return uint64(header.Symndx), nil
		}

		// Follow chain to find highest symbol index
		currentSymIndex := uint64(maxBucketIndex)
		for currentSymIndex < 1000000 {
			chainIndex := currentSymIndex - uint64(header.Symndx)
			if _, err := r.File.Seek(int64(chainsOffset+chainIndex*4), io.SeekStart); err != nil {
				return currentSymIndex, nil
			}

			var chainVal uint32
			if err := binary.Read(r.File, binary.LittleEndian, &chainVal); err != nil {
				return currentSymIndex, nil
			}

			// Bit 0 = 1 marks end of chain
			if (chainVal & 1) != 0 {
				return currentSymIndex + 1, nil
			}
			currentSymIndex++
		}

		return currentSymIndex + 1, nil
	}

	return 0, fmt.Errorf("sym:count | missing DT_HASH or DT_GNU_HASH")
}

// readStrtabString reads a null-terminated string from the string table at the given name offset
func (r *ElfReader) readStrtabString(nameOffset uint32) string {
	if nameOffset == 0 || r.strtabOffset == 0 {
		return ""
	}

	fileInfo, err := r.File.Stat()
	if err != nil {
		logger.Warn("strtab:read | stat failed", "error", err)
		return ""
	}

	offset := r.strtabOffset + uint64(nameOffset)
	if offset >= uint64(fileInfo.Size()) {
		logger.Warn("strtab:read | offset out of bounds", "offset", fmt.Sprintf("0x%x", offset), "fileSize", fileInfo.Size())
		return ""
	}

	if _, err = r.File.Seek(int64(offset), io.SeekStart); err != nil {
		logger.Warn("strtab:read | seek failed", "offset", fmt.Sprintf("0x%x", offset), "error", err)
		return ""
	}

	var result []byte
	buf := make([]byte, 1)
	maxLen := 1024

	for len(result) < maxLen {
		if _, err := r.File.Read(buf); err != nil || buf[0] == 0 {
			break
		}
		result = append(result, buf[0])
	}

	if len(result) >= maxLen {
		logger.Warn("strtab:read | truncated", "maxLen", maxLen)
	}

	return string(result)
}

// ResolveMetadata resolves offsets for strings like soname, needed libs, and runpath
func (r *ElfReader) ResolveMetadata() {
	for _, entry := range r.Dyns {
		switch entry.Tag {
		case DT_NEEDED:
			lib := r.readString(uint32(entry.Val))
			if lib != "" {
				r.neededLibs = append(r.neededLibs, lib)
				logger.Info("dep:needed", "lib", lib)
			}
		case DT_SONAME:
			r.soname = r.readString(uint32(entry.Val))
			logger.Info("dep:soname", "name", r.soname)
		case DT_RUNPATH:
			r.runpath = r.readString(uint32(entry.Val))
			logger.Info("dep:runpath", "path", r.runpath)
		}
	}
}

// readString reads a null-terminated string from the file's string table at the given offset
func (r *ElfReader) readString(offset uint32) string {
	if r.strtabOffset == 0 || offset == 0 {
		return ""
	}

	// Calculate absolute file offset
	vaddr := r.strtabOffset + uint64(offset)
	fileOffset := uint64(0)
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && vaddr >= phdr.Vaddr && vaddr < phdr.Vaddr+phdr.Memsz {
			fileOffset = phdr.Offset + (vaddr - phdr.Vaddr)
			break
		}
	}

	if fileOffset == 0 {
		return ""
	}

	// Read until null terminator
	str := ""
	buf := make([]byte, 1)
	for {
		n, err := r.File.ReadAt(buf, int64(fileOffset))
		if err != nil || n == 0 || buf[0] == 0 {
			break
		}
		str += string(buf[0])
		fileOffset++
	}
	return str
}

// readIntoArray reads up to 'count' elements of type T from file at the given offset.
// Returns the successfully read elements and the actual count. On EOF, returns partial results without error.
func readArray[T any](file *os.File, offset uint64, count uint64, name string) ([]T, error) {
	if count == 0 {
		return []T{}, nil
	}

	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to %s at 0x%x: %w", name, offset, err)
	}

	// Try to read the full array first (most efficient for common case)
	array := make([]T, count)
	if err := binary.Read(file, binary.LittleEndian, array); err == nil {
		return array, nil
	}

	// On error, fall back to reading element by element for partial results
	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to %s at 0x%x: %w", name, offset, err)
	}

	result := make([]T, 0, count)
	for i := uint64(0); i < count; i++ {
		var elem T
		if err := binary.Read(file, binary.LittleEndian, &elem); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// Return what we have so far
				if len(result) > 0 {
					logger.Warn("partial read", "name", name, "expected", count, "got", len(result))
				}
				return result, nil
			}
			return nil, fmt.Errorf("failed to read %s element %d at 0x%x: %w", name, i, offset, err)
		}
		result = append(result, elem)
	}

	return result, nil
}
