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
	// Create custom styles for the logger
	styles := log.DefaultStyles()

	// Catppuccin Mocha inspired colors for log levels
	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().
		SetString("DEBG").
		Foreground(lipgloss.Color("243")) // Grey
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().
		SetString("INFO").
		Foreground(lipgloss.Color("86")) // Cyan
	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().
		SetString("WARN").
		Foreground(lipgloss.Color("221")) // Yellow
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("ERROR").
		Foreground(lipgloss.Color("#f38ba8")) // Red

	// Style for keys and values
	styles.Key = lipgloss.NewStyle().Foreground(lipgloss.Color("#585b70"))
	styles.Value = lipgloss.NewStyle().Foreground(lipgloss.Color("#b4befe"))

	for _, key := range []string{"vaddr", "addr", "offset", "base", "from", "to", "end", "final_va", "maxSegmentEnd"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#fab387")).Transform(func(s string) string {
			if num, err := strconv.Atoi(s); err == nil {
				return fmt.Sprintf("0x%x", num)
			}
			return s
		})
	}
	for _, key := range []string{"type", "tag", "reloc", "bind"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa")).Bold(true)
	}
	for _, key := range []string{"file", "path"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#f9e2af"))
	}
	for _, key := range []string{"name"} {
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

	// .hash and .gnu.hash
	hashOffset    uint64
	hashSize      uint64
	gnuHashOffset uint64
	gnuHashSize   uint64

	// .dynamic section
	dynamicOffset uint64
	dynamicSize   uint64

	// PT_GNU_RELRO
	relroOffset uint64
	relroSize   uint64

	// .strtab size
	strtabSize uint64

	newStrtabMap map[string]uint32
	newStrtab    []byte
	newSymbols   []Elf64_Sym
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
func FixELFHeaders(filePath string, baseAddr uint64, outputPath string, debug bool) error {
	if debug {
		logger.SetLevel(log.DebugLevel)
	} else {
		logger.SetLevel(log.InfoLevel)
	}
	logger.Info("Starting ELF fix", "file", filePath, "base", baseAddr)

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
	logger.Info("Reading and validating ELF header")
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
	logger.Info("ELF header validated", "class", "64-bit", "phentsize", r.ElfHeader.Phentsize)

	return nil
}

func (r *ElfReader) ReadPhdrs() error {
	phtSize := uint64(r.ElfHeader.Phnum) * uint64(r.ElfHeader.Phentsize)
	if phtSize == 0 || r.ElfHeader.Phnum > 1024 {
		return fmt.Errorf("invalid number of program headers: %d", r.ElfHeader.Phnum)
	}
	logger.Info("Reading PHT", "offset", r.ElfHeader.PhdrOffset, "entries", r.ElfHeader.Phnum)

	var err error
	if r.Phdrs, err = readArray[Elf64_Phdr](r.File, r.ElfHeader.PhdrOffset, uint64(r.ElfHeader.Phnum), "PT_PHDR"); err != nil {
		return err
	}

	for i := range r.Phdrs {
		phdr := &r.Phdrs[i]

		if phdr.Type == PT_LOAD && r.phdrPtLoadPageStart == 0 {
			r.phdrPtLoadPageStart = PageStart(phdr.Vaddr)
		}

		if phdr.Type == PT_GNU_RELRO {
			r.relroOffset = phdr.Vaddr
			r.relroSize = phdr.Memsz

			// Fix RELRO offset based on parent PT_LOAD
			for _, parent := range r.Phdrs {
				if parent.Type == PT_LOAD && phdr.Vaddr >= parent.Vaddr && (phdr.Vaddr+phdr.Memsz) <= (parent.Vaddr+parent.Memsz) {
					expectedOffset := parent.Offset + (phdr.Vaddr - parent.Vaddr)
					if phdr.Offset != expectedOffset {
						logger.Debug("Fixing PT_GNU_RELRO offset", "from", fmt.Sprintf("0x%x", phdr.Offset), "to", fmt.Sprintf("0x%x", expectedOffset))
						phdr.Offset = expectedOffset
					}
					break
				}
			}
		}

		logger.Debug("  + header", "type", phdr.Type.Text(), "offset", phdr.Offset)
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
		return nil
	}

	entryCount := dynamicPhdr.Memsz / uint64(binary.Size(Elf64_Dyn{}))
	logger.Info("Reading DYN", "offset", dynamicPhdr.Offset, "entries", entryCount)

	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero size")
	}
	logger.Debug("Dynamic section found", "vaddr", dynamicPhdr.Vaddr, "offset", dynamicPhdr.Offset, "entries", entryCount)

	// Store dynamic section info
	r.dynamicOffset = dynamicPhdr.Vaddr
	r.dynamicSize = dynamicPhdr.Memsz

	// Read the dynamic section content
	var err error
	if r.Dyns, err = readArray[Elf64_Dyn](r.File, r.dynamicOffset, entryCount, "DT_DYNAMIC"); err != nil {
		return err
	}

	r.dynMap = make(map[DT_Tag]uint64)
	for _, entry := range r.Dyns {
		baseLog := entry.Val
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
		case DT_PLTGOT:
			r.gotOffset = entry.Val
		case DT_INIT_ARRAY:
			r.initArrayOffset = entry.Val
		case DT_INIT_ARRAYSZ:
			r.initArraySize = entry.Val
		case DT_FINI_ARRAY:
			r.finiArrayOffset = entry.Val
		case DT_FINI_ARRAYSZ:
			r.finiArraySize = entry.Val
		case DT_HASH:
			r.hashOffset = entry.Val
		case DT_GNU_HASH:
			r.gnuHashOffset = entry.Val
		case DT_STRSZ:
			r.strtabSize = entry.Val
		}
		logger.Debug("  + dynamic", "tag", entry.Tag.Text(), "val", baseLog)
		r.dynMap[entry.Tag] = entry.Val
	}

	return nil
}

func (r *ElfReader) ReadRelocs() error {
	var err error
	if r.symCount, err = calculateSymbolCount(r.File, r.dynMap); err != nil {
		return fmt.Errorf("failed to calculate symbol count: %w", err)
	}

	logger.Info("Found symbols", "count", r.symCount)
	if r.Symbols, err = readArray[Elf64_Sym](r.File, r.symtabOffset, r.symCount, "DT_SYMTAB"); err != nil {
		return err
	}

	if r.relOffset != 0 {
		relCount := r.relSize / uint64(binary.Size(Elf64_Rel{}))
		logger.Info("  +", "reloc", "DT_REL", "offset", r.relOffset, "count", relCount)
		if r.Rel, err = readArray[Elf64_Rel](r.File, r.relOffset, relCount, "DT_REL"); err != nil {
			return err
		}
	}
	if r.relaOffset != 0 {
		relaCount := r.relaSize / uint64(binary.Size(Elf64_Rela{}))
		logger.Info("  +", "reloc", "DT_RELA", "offset", r.relaOffset, "count", relaCount)
		if r.Rela, err = readArray[Elf64_Rela](r.File, r.relaOffset, relaCount, "DT_RELA"); err != nil {
			return err
		}
	}
	if r.jmprelOffset != 0 {
		if r.jmprelEntry == 16 {
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rel{}))
			logger.Info("  +", "reloc", "DT_JMPREL", "offset", r.jmprelOffset, "count", jmprelCount)
			if r.JmpRel, err = readArray[Elf64_Rel](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
		} else {
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rela{}))
			logger.Info("  +", "reloc", "DT_JMPREL", "offset", r.jmprelOffset, "count", jmprelCount)
			if r.JmpRela, err = readArray[Elf64_Rela](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
		}
	}

	// Calculate .hash size from its header
	if r.hashOffset != 0 {
		size, err := calculateHashSize(r.File, r.hashOffset)
		if err == nil {
			r.hashSize = size
		}
	}

	// Calculate .gnu.hash size from its header and symCount
	if r.gnuHashOffset != 0 {
		size, err := calculateGnuHashSize(r.File, r.gnuHashOffset, r.symCount)
		if err == nil {
			r.gnuHashSize = size
		}
	}

	// Calculate .got size: 3 reserved entries + number of PLT entries
	// Each entry is 8 bytes on 64-bit
	if r.gotOffset != 0 {
		pltEntries := uint64(0)
		if r.jmprelEntry > 0 && r.jmprelSize > 0 {
			pltEntries = r.jmprelSize / r.jmprelEntry
		}
		r.gotSize = (3 + pltEntries) * 8
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
		L := base + rel.Offset
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
		case R_AARCH64_RELATIVE:
			P = L
		default:
			P = S
		}

		rel.Offset = P
		logger.Debug("  +rel", "type", relocType.Text(), "sym", rname, "final_va", P)
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
		logger.Debug("  + rela", "type", relocType.Text(), "sym", rname, "final_va", P)

	}

	// --- Execute Relocations ---
	for i := range r.Rel {
		fnRel(&r.Rel[i])
	}
	for i := range r.Rela {
		fnRela(&r.Rela[i])
	}
	for i := range r.JmpRel {
		fnRel(&r.JmpRel[i])
	}
	for i := range r.JmpRela {
		fnRela(&r.JmpRela[i])
	}

	return nil
}

// BuildStrtab builds a new string table with all symbol names
func (r *ElfReader) BuildStrtab() error {
	logger.Info("Building new string table")

	if len(r.Symbols) == 0 {
		logger.Warn("No symbols to process, skipping string table build")
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
		// Skip the first symbol (null symbol) since we already added it
		if i == 0 {
			continue
		}
		// Skip empty/null entries
		if sym.St_Name == 0 && sym.St_Value == 0 && sym.St_Size == 0 {
			continue
		}

		// Read original symbol name
		symName := readStrtabString(r.File, r.strtabOffset, sym.St_Name)

		logger.Debug("Symbol", "idx", i, "name", symName, "value", sym.St_Value, "bind", sym.stBind().Text())

		// Update name offset in new strtab
		sym.St_Name = addString(symName)

		// Separate local and global symbols (ELF requires locals first)
		bind := sym.stBind()
		if bind == STB_LOCAL {
			localSymbols = append(localSymbols, sym)
		} else {
			globalSymbols = append(globalSymbols, sym)
		}
	}

	// Add local symbols first, then global
	r.newSymbols = append(r.newSymbols, localSymbols...)
	r.newSymbols = append(r.newSymbols, globalSymbols...)

	logger.Info("Built string table", "size", len(r.newStrtab), "null", 1, "local", len(localSymbols), "global", len(globalSymbols))

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

	if hashOffset != 0 {
		var header HashHeader
		logger.Info("Using DT_HASH for symbol count")

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
		logger.Info("Using DT_GNU_HASH for symbol count")

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
