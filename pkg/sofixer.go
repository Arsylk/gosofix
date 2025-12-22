package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"

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
	logger.Info("Starting ELF fix", "file", filePath, "base", baseAddr)

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
	logger.Info("Reading and validating ELF header")
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
	logger.Info("ELF header validated", "class", "64-bit", "arch", "AArch64", "type", "shared object", "phentsize", r.ElfHeader.Phentsize)

	return nil
}

func (r *ElfReader) ReadPhdrs() error {
	phtSize := uint64(r.ElfHeader.Phnum) * uint64(r.ElfHeader.Phentsize)
	if phtSize == 0 {
		return fmt.Errorf("no program headers found")
	}
	if r.ElfHeader.Phnum > 1024 {
		return fmt.Errorf("too many program headers: %d (max 1024)", r.ElfHeader.Phnum)
	}
	logger.Info("Reading PHT", "offset", r.ElfHeader.PhdrOffset, "entries", r.ElfHeader.Phnum)

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

		if phdr.Type == PT_LOAD && r.phdrPtLoadPageStart == 0 {
			r.phdrPtLoadPageStart = PageStart(phdr.Vaddr)
		}

		if phdr.Type == PT_GNU_EH_FRAME {
			r.ehFrameHdrOffset = phdr.Vaddr
			r.ehFrameHdrSize = phdr.Memsz
			logger.Info("Found PT_GNU_EH_FRAME", "vaddr", fmt.Sprintf("0x%x", phdr.Vaddr), "size", phdr.Memsz)
		}

		if phdr.Type == PT_NOTE {
			r.NoteSegments = append(r.NoteSegments, AddrRange{Start: phdr.Vaddr, End: phdr.Vaddr + phdr.Memsz, Name: ".note"})
			if r.noteOffset == 0 {
				r.noteOffset = phdr.Vaddr
				r.noteSize = phdr.Memsz
			}
			logger.Info("Found PT_NOTE", "vaddr", fmt.Sprintf("0x%x", phdr.Vaddr), "size", phdr.Memsz)
		}

		if phdr.Type == PT_TLS {
			r.tlsOffset = phdr.Vaddr
			r.tlsSize = phdr.Memsz
			logger.Info("Found PT_TLS", "vaddr", fmt.Sprintf("0x%x", phdr.Vaddr), "size", phdr.Memsz)
		}

		if phdr.Type == PT_GNU_RELRO {
			r.relroAddr = phdr.Vaddr
			r.relroSize = phdr.Memsz
			logger.Info("Found PT_GNU_RELRO", "vaddr", fmt.Sprintf("0x%x", phdr.Vaddr), "size", phdr.Memsz)
		}

		logger.Debug("  + header", "type", phdr.Type.Text(), "offset", phdr.Offset)
	}

	return nil
}

// normalizeAddr converts an absolute address to a relative offset if it's above BaseAddr
func (r *ElfReader) normalizeAddr(addr uint64) uint64 {
	if addr >= r.BaseAddr {
		return addr - r.BaseAddr
	}
	return addr
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
		logger.Warn("No dynamic section found")
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
		val := entry.Val
		// Normalize addresses if they appear to be absolute
		switch entry.Tag {
		case DT_STRTAB, DT_SYMTAB, DT_REL, DT_RELA, DT_JMPREL,
			DT_PLTGOT, DT_INIT_ARRAY, DT_FINI_ARRAY,
			DT_HASH, DT_GNU_HASH, DT_VERSYM, DT_VERNEED:
			if val >= r.BaseAddr {
				normVal := val - r.BaseAddr
				logger.Debug("Normalizing dynamic tag", "tag", entry.Tag.Text(), "old", fmt.Sprintf("0x%x", val), "new", fmt.Sprintf("0x%x", normVal))
				val = normVal
			}
		}

		switch entry.Tag {
		case DT_STRTAB:
			r.strtabOffset = val
		case DT_SYMTAB:
			r.symtabOffset = val
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
		case DT_PLTGOT:
			r.gotOffset = val
		case DT_INIT_ARRAY:
			r.initArrayOffset = val
		case DT_INIT_ARRAYSZ:
			r.initArraySize = val
		case DT_FINI_ARRAY:
			r.finiArrayOffset = val
		case DT_FINI_ARRAYSZ:
			r.finiArraySize = val
		case DT_INIT:
			r.initFunc = val // Single function pointer
		case DT_FINIT:
			r.finiFunc = val // Single function pointer
		case DT_PREINIT_ARRAY:
			r.preinitArrayOffset = val
		case DT_PREINIT_ARRAYSZ:
			r.preinitArraySize = val
		case DT_HASH:
			r.hashOffset = val
		case DT_GNU_HASH:
			r.gnuHashOffset = val
		case DT_STRSZ:
			r.strtabSize = val
		case DT_VERSYM:
			r.versymOffset = val
		case DT_VERNEED:
			r.verneedOffset = val
		case DT_VERNEEDNUM:
			r.verneedNum = uint16(val)
		case DT_FLAGS:
			r.flags = val
		case DT_FLAGS_1:
			r.flags1 = val
		case DT_SONAME:
		case DT_RUNPATH:
		case DT_NEEDED:
		case DT_RELACOUNT:
			r.dtRelaCount = val
		case DT_RELCOUNT:
			r.dtRelCount = val
		}
		logger.Debug("  + dynamic", "tag", entry.Tag.Text(), "val", val)
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

	r.calculateSectionSizes()
	r.calculatePltInfo()
	r.calculateTextSection()
	r.analyzeDataSections()
	r.ResolveMetadata()
	r.ReadVersioningMetadata()

	return nil
}

// collectOccupiedRanges returns all virtual address ranges already known/claimed
func (r *ElfReader) collectOccupiedRanges() []AddrRange {
	var ranges []AddrRange

	// PT_LOAD segments that usually contain headers/metadata
	// For now, we focus on ranges we explicitly identify as sections

	if r.dynamicOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.dynamicOffset, End: r.dynamicOffset + r.dynamicSize, Name: ".dynamic"})
	}
	if r.gotOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.gotOffset, End: r.gotOffset + r.gotSize, Name: ".got"})
	}
	if r.pltAddr != 0 {
		ranges = append(ranges, AddrRange{Start: r.pltAddr, End: r.pltAddr + r.pltSize, Name: ".plt"})
	}
	if r.initArrayOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.initArrayOffset, End: r.initArrayOffset + r.initArraySize, Name: ".init_array"})
	}
	if r.finiArrayOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.finiArrayOffset, End: r.finiArrayOffset + r.finiArraySize, Name: ".fini_array"})
	}
	if r.hashOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.hashOffset, End: r.hashOffset + r.hashSize, Name: ".hash"})
	}
	if r.gnuHashOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.gnuHashOffset, End: r.gnuHashOffset + r.gnuHashSize, Name: ".gnu.hash"})
	}
	if r.symtabOffset != 0 {
		// Note: new symtab might have different size, but here we track dump locations
		ranges = append(ranges, AddrRange{Start: r.symtabOffset, End: r.symtabOffset + uint64(len(r.newSymbols)*24), Name: ".dynsym"})
	}
	if r.strtabOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.strtabOffset, End: r.strtabOffset + uint64(len(r.newStrtab)), Name: ".dynstr"})
	}
	if r.ehFrameHdrOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.ehFrameHdrOffset, End: r.ehFrameHdrOffset + r.ehFrameHdrSize, Name: ".eh_frame_hdr"})

		// .eh_frame follows .eh_frame_hdr - calculate its precise size
		r.calculateEhFrameSection()
		if r.ehFrameOffset != 0 && r.ehFrameSize > 0 {
			ranges = append(ranges, AddrRange{Start: r.ehFrameOffset, End: r.ehFrameOffset + r.ehFrameSize, Name: ".eh_frame"})
		}
	}
	if len(r.NoteSegments) > 0 {
		ranges = append(ranges, r.NoteSegments...)
	} else if r.noteOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.noteOffset, End: r.noteOffset + r.noteSize, Name: ".note.gnu.build-id"})
	}
	if r.relOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.relOffset, End: r.relOffset + r.relSize, Name: ".rel.dyn"})
	}
	if r.relaOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.relaOffset, End: r.relaOffset + r.relaSize, Name: ".rela.dyn"})
	}
	if r.jmprelOffset != 0 {
		ranges = append(ranges, AddrRange{Start: r.jmprelOffset, End: r.jmprelOffset + r.jmprelSize, Name: ".rel.plt"})
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start < ranges[j].Start
	})

	return ranges
}

// findExecutableSegments returns all PT_LOAD segments with execute permission
func (r *ElfReader) findExecutableSegments() []Elf64_Phdr {
	var execSegments []Elf64_Phdr
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && (phdr.Flags&PF_X) != 0 && (phdr.Flags&PF_R) != 0 {
			execSegments = append(execSegments, phdr)
		}
	}
	return execSegments
}

// findLargestGap finds the largest unoccupied address range within a segment.
// It skips over all occupied ranges and returns the largest gap found.
func (r *ElfReader) findLargestGap(segStart, segEnd uint64, occupied []AddrRange) (gapStart, gapSize uint64) {
	current := segStart

	// Skip ELF headers if segment starts at 0
	if current == 0 {
		headerEnd := uint64(r.ElfHeader.Ehsize) + uint64(r.ElfHeader.Phnum)*uint64(r.ElfHeader.Phentsize)
		headerEnd = alignUp(headerEnd, 16)
		current = headerEnd
	}

	bestGapStart, bestGapSize := uint64(0), uint64(0)

	for _, occ := range occupied {
		if occ.End <= current {
			continue // This range already passed
		}
		if occ.Start >= segEnd {
			break // Beyond this segment
		}

		// Found a gap before this occupied range
		if occ.Start > current {
			gap := occ.Start - current
			if gap > bestGapSize {
				bestGapSize = gap
				bestGapStart = current
			}
		}

		// Move past this occupied range
		if occ.End > current {
			current = occ.End
		}
	}

	// Check for gap at the end
	if current < segEnd {
		gap := segEnd - current
		if gap > bestGapSize {
			bestGapSize = gap
			bestGapStart = current
		}
	}

	return bestGapStart, bestGapSize
}

// calculateTextSection finds the largest executable gap to designate as .text
// This method identifies unoccupied address ranges in executable segments and
// designates the largest one as the .text section for reverse engineering purposes.
func (r *ElfReader) calculateTextSection() {
	occupied := r.collectOccupiedRanges()
	execSegments := r.findExecutableSegments()

	var bestGapStart, bestGapSize uint64

	for _, phdr := range execSegments {
		gapStart, gapSize := r.findLargestGap(phdr.Vaddr, phdr.Vaddr+phdr.Memsz, occupied)

		if gapSize > bestGapSize {
			bestGapSize = gapSize
			bestGapStart = gapStart
		}
	}

	if bestGapSize > 0 {
		r.textAddr = bestGapStart
		r.textSize = bestGapSize
		logger.Info("[?] found .text section", "addr", fmt.Sprintf("0x%x", r.textAddr), "size", r.textSize)
	}
}

// calculateEhFrameSection calculates the .eh_frame section location and precise size
// It typically follows immediately after .eh_frame_hdr
func (r *ElfReader) calculateEhFrameSection() {
	if r.ehFrameHdrOffset == 0 || r.ehFrameOffset != 0 {
		return // Already calculated or not available
	}

	// .eh_frame starts right after .eh_frame_hdr (aligned to 8 bytes)
	ehFrameStart := alignUp(r.ehFrameHdrOffset+r.ehFrameHdrSize, 8)

	// Parse the .eh_frame precisely
	size, err := r.calculateEhFrameSize(ehFrameStart)
	if err != nil {
		logger.Warn("Failed to calculate precise .eh_frame size", "error", err)
		return
	}

	if size > 0 {
		r.ehFrameOffset = ehFrameStart
		r.ehFrameSize = size
		logger.Info("Calculated precise .eh_frame section", "addr", fmt.Sprintf("0x%x", r.ehFrameOffset), "size", r.ehFrameSize)
	}
}

// calculateEhFrameSize parses the .eh_frame data to find its exact end
func (r *ElfReader) calculateEhFrameSize(start uint64) (uint64, error) {
	// Find file offset for the virtual address
	fileOffset := uint64(0)
	maxVaddr := uint64(0)
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && start >= phdr.Vaddr && start < phdr.Vaddr+phdr.Memsz {
			fileOffset = phdr.Offset + (start - phdr.Vaddr)
			maxVaddr = phdr.Vaddr + phdr.Memsz
			break
		}
	}

	if fileOffset == 0 {
		return 0, fmt.Errorf("could not find file offset for .eh_frame start at 0x%x", start)
	}

	currVaddr := start
	currFileOffset := fileOffset

	for {
		// Ensure we don't go past segment boundary
		if currVaddr+4 > maxVaddr {
			break
		}

		// Read length (4 bytes)
		var length uint32
		if _, err := r.File.Seek(int64(currFileOffset), io.SeekStart); err != nil {
			return 0, err
		}
		if err := binary.Read(r.File, binary.LittleEndian, &length); err != nil {
			return 0, err
		}

		if length == 0 {
			// End of .eh_frame entries
			currVaddr += 4
			currFileOffset += 4
			break
		}

		entrySize := uint64(0)
		if length == 0xffffffff {
			// 64-bit DWARF
			if currVaddr+12 > maxVaddr {
				break
			}
			var length64 uint64
			if err := binary.Read(r.File, binary.LittleEndian, &length64); err != nil {
				return 0, err
			}
			entrySize = length64 + 12
		} else {
			entrySize = uint64(length) + 4
		}

		currVaddr += entrySize
		currFileOffset += entrySize

		if currVaddr >= maxVaddr {
			break
		}
	}

	return currVaddr - start, nil
}

// analyzeDataSections identifies all header-only sections (.dynamic, .got, .data, .bss, etc)
func (r *ElfReader) analyzeDataSections() {
	r.computedSections = nil

	// 1. Fixed metadata sections
	if r.ehFrameHdrOffset != 0 && r.ehFrameHdrSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".eh_frame_hdr", Type: SHT_PROGBITS, Flags: SHF_ALLOC,
			Addr: r.ehFrameHdrOffset, Size: r.ehFrameHdrSize, Addralign: 4,
		})

		// .eh_frame typically follows .eh_frame_hdr
		// Calculate its location by finding the next section boundary
		r.calculateEhFrameSection()
	}
	if len(r.NoteSegments) > 0 {
		for i, ns := range r.NoteSegments {
			name := ".note.gnu.build-id"
			if i > 0 {
				name = fmt.Sprintf(".note.%d", i)
			}
			r.computedSections = append(r.computedSections, ComputedSection{
				Name: name, Type: SHT_NOTE, Flags: SHF_ALLOC,
				Addr: ns.Start, Size: ns.End - ns.Start, Addralign: 4,
			})
		}
	} else if r.noteOffset != 0 && r.noteSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".note.gnu.build-id", Type: SHT_NOTE, Flags: SHF_ALLOC,
			Addr: r.noteOffset, Size: r.noteSize, Addralign: 4,
		})
	}

	// Add .eh_frame if we calculated it
	if r.ehFrameOffset != 0 && r.ehFrameSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".eh_frame", Type: SHT_PROGBITS, Flags: SHF_ALLOC,
			Addr: r.ehFrameOffset, Size: r.ehFrameSize, Addralign: 8,
		})
	}

	// 2. Dynamic sections
	if r.dynamicOffset != 0 && r.dynamicSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".dynamic", Type: SHT_DYNAMIC, Flags: SHF_ALLOC | SHF_WRITE,
			Addr: r.dynamicOffset, Size: r.dynamicSize, Addralign: 8, Entsize: 16,
		})
	}
	if r.gotOffset != 0 && r.gotSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".got", Type: SHT_PROGBITS, Flags: SHF_ALLOC | SHF_WRITE,
			Addr: r.gotOffset, Size: r.gotSize, Addralign: 8, Entsize: 8,
		})
	}
	if r.initArrayOffset != 0 && r.initArraySize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".init_array", Type: SHT_INIT_ARRAY, Flags: SHF_ALLOC | SHF_WRITE,
			Addr: r.initArrayOffset, Size: r.initArraySize, Addralign: 8, Entsize: 8,
		})
	}
	if r.finiArrayOffset != 0 && r.finiArraySize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".fini_array", Type: SHT_FINI_ARRAY, Flags: SHF_ALLOC | SHF_WRITE,
			Addr: r.finiArrayOffset, Size: r.finiArraySize, Addralign: 8, Entsize: 8,
		})
	}

	// 2.5. Versioning sections - Link field will be set later by rebuilder to point to .dynsym
	if r.versymOffset != 0 && r.symCount > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".gnu.version", Type: SHT_GNU_VERSYM, Flags: SHF_ALLOC,
			Addr: r.versymOffset, Size: r.symCount * 2, Addralign: 2, Entsize: 2,
			// Link will be set to .dynsym index by rebuilder
		})
	}

	// 3. PLT and Text
	if r.pltAddr != 0 && r.pltSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".plt", Type: SHT_PROGBITS, Flags: SHF_ALLOC | SHF_EXECINSTR,
			Addr: r.pltAddr, Size: r.pltSize, Addralign: 16,
		})
	}
	if r.textAddr != 0 && r.textSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".text", Type: SHT_PROGBITS, Flags: SHF_ALLOC | SHF_EXECINSTR,
			Addr: r.textAddr, Size: r.textSize, Addralign: 16,
		})
	}

	// 4. Collect all data and BSS ranges from writable segments, then merge into single sections
	var dataRanges []AddrRange
	var bssRanges []AddrRange

	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && (phdr.Flags&PF_W) != 0 {
			// Collect .data range
			if phdr.Filesz > 0 {
				addr := phdr.Vaddr
				size := phdr.Filesz
				// Skip headers if this segment starts at 0
				if addr == 0 {
					headerSize := uint64(r.ElfHeader.Ehsize) + uint64(r.ElfHeader.Phnum)*uint64(r.ElfHeader.Phentsize)
					headerSize = (headerSize + 15) &^ 15
					addr += headerSize
					size -= headerSize
				}
				if size > 0 {
					dataRanges = append(dataRanges, AddrRange{Start: addr, End: addr + size, Name: ".data"})
				}
			}
			// Collect .bss range
			if phdr.Memsz > phdr.Filesz {
				bssAddr := phdr.Vaddr + phdr.Filesz
				bssSize := phdr.Memsz - phdr.Filesz
				bssRanges = append(bssRanges, AddrRange{Start: bssAddr, End: bssAddr + bssSize, Name: ".bss"})
			}
		}
	}

	// 5. Separate .data.rel.ro if PT_GNU_RELRO is present
	if r.relroAddr != 0 && r.relroSize > 0 {
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".data.rel.ro", Type: SHT_PROGBITS, Flags: SHF_ALLOC | SHF_WRITE,
			Addr: r.relroAddr, Size: r.relroSize, Addralign: 16,
		})

		// Split dataRanges to exclude the RELRO part
		var newDataRanges []AddrRange
		for _, dr := range dataRanges {
			// If RELRO is inside or overlaps with this range
			if r.relroAddr >= dr.Start && r.relroAddr < dr.End {
				// Part before RELRO
				if r.relroAddr > dr.Start {
					newDataRanges = append(newDataRanges, AddrRange{Start: dr.Start, End: r.relroAddr, Name: ".data"})
				}
				// Part after RELRO
				relroEnd := r.relroAddr + r.relroSize
				if relroEnd < dr.End {
					newDataRanges = append(newDataRanges, AddrRange{Start: relroEnd, End: dr.End, Name: ".data"})
				}
			} else {
				newDataRanges = append(newDataRanges, dr)
			}
		}
		dataRanges = newDataRanges
	}

	// Merge and create single .data section
	if len(dataRanges) > 0 {
		minAddr := dataRanges[0].Start
		maxEnd := dataRanges[0].End
		for _, dataRange := range dataRanges {
			if dataRange.Start < minAddr {
				minAddr = dataRange.Start
			}
			if dataRange.End > maxEnd {
				maxEnd = dataRange.End
			}
		}
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".data", Type: SHT_PROGBITS, Flags: SHF_ALLOC | SHF_WRITE,
			Addr: minAddr, Size: maxEnd - minAddr, Addralign: 16,
		})
		logger.Info("Merged .data section", "ranges", len(dataRanges), "addr", fmt.Sprintf("0x%x", minAddr), "size", maxEnd-minAddr)
	}

	// Merge and create single .bss section
	if len(bssRanges) > 0 {
		minAddr := bssRanges[0].Start
		maxEnd := bssRanges[0].End
		for _, bssRange := range bssRanges {
			if bssRange.Start < minAddr {
				minAddr = bssRange.Start
			}
			if bssRange.End > maxEnd {
				maxEnd = bssRange.End
			}
		}
		r.computedSections = append(r.computedSections, ComputedSection{
			Name: ".bss", Type: SHT_NOBITS, Flags: SHF_ALLOC | SHF_WRITE,
			Addr: minAddr, Size: maxEnd - minAddr, Addralign: 16,
		})
		logger.Info("Merged .bss section", "ranges", len(bssRanges), "addr", fmt.Sprintf("0x%x", minAddr), "size", maxEnd-minAddr)
	}
}

// readSymbols reads the symbol table
func (r *ElfReader) readSymbols() error {
	var err error
	if r.symCount, err = calculateSymbolCount(r.File, r.dynMap); err != nil {
		return fmt.Errorf("failed to calculate symbol count: %w", err)
	}

	if r.symCount == 0 {
		logger.Warn("No symbols found")
		return nil
	}

	logger.Info("Found symbols", "count", r.symCount)
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
		logger.Info("Reading DT_REL", "offset", r.relOffset, "count", relCount)
		if r.Rel, err = readArray[Elf64_Rel](r.File, r.relOffset, relCount, "DT_REL"); err != nil {
			return err
		}
	}

	if r.relaOffset != 0 {
		relaCount := r.relaSize / uint64(binary.Size(Elf64_Rela{}))
		logger.Info("Reading DT_RELA", "offset", r.relaOffset, "count", relaCount)
		if r.Rela, err = readArray[Elf64_Rela](r.File, r.relaOffset, relaCount, "DT_RELA"); err != nil {
			return err
		}
	}

	if r.jmprelOffset != 0 {
		if r.jmprelEntry == 16 {
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rel{}))
			logger.Info("Reading DT_JMPREL", "offset", r.jmprelOffset, "count", jmprelCount, "type", "REL")
			if r.JmpRel, err = readArray[Elf64_Rel](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
		} else {
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rela{}))
			logger.Info("Reading DT_JMPREL", "offset", r.jmprelOffset, "count", jmprelCount, "type", "RELA")
			if r.JmpRela, err = readArray[Elf64_Rela](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
		}
	}

	return nil
}

// calculateSectionSizes computes sizes for .hash, .gnu.hash, and .got sections
func (r *ElfReader) calculateSectionSizes() {
	// Calculate .hash size
	if r.hashOffset != 0 {
		if size, err := calculateHashSize(r.File, r.hashOffset); err == nil {
			r.hashSize = size
		}
	}

	// Calculate .gnu.hash size
	if r.gnuHashOffset != 0 {
		if size, err := calculateGnuHashSize(r.File, r.gnuHashOffset, r.symCount); err == nil {
			r.gnuHashSize = size
		}
	}

	// Calculate .got size: 3 reserved + PLT entries
	if r.gotOffset != 0 {
		pltEntries := uint64(0)
		if r.jmprelEntry > 0 && r.jmprelSize > 0 {
			pltEntries = r.jmprelSize / r.jmprelEntry
		}
		r.gotSize = (3 + pltEntries) * 8
	}
}

// calculatePltInfo computes PLT address and size
func (r *ElfReader) calculatePltInfo() {
	if r.jmprelSize == 0 || r.jmprelEntry == 0 {
		return
	}

	pltCount := r.jmprelSize / r.jmprelEntry
	r.pltSize = ARM64_PLT0_SIZE + (pltCount * ARM64_PLT_ENTRY_SIZE)

	// PLT usually follows .rela.plt immediately (16-byte aligned)
	estimatedPltAddr := alignUp(r.jmprelOffset+r.jmprelSize, 16)

	// Verify it's in an executable segment
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && (phdr.Flags&PF_X) != 0 {
			if estimatedPltAddr >= phdr.Vaddr && estimatedPltAddr < phdr.Vaddr+phdr.Memsz {
				r.pltAddr = estimatedPltAddr
				logger.Info("Calculated PLT", "addr", fmt.Sprintf("0x%x", r.pltAddr), "size", r.pltSize)
				return
			}
		}
	}

	logger.Warn("Could not determine PLT address safely")
}

func (r *ElfReader) FixRelocs(base uint64) error {
	logger.Info("Fixing relocations", "base", base)

	r.fixRelArray(r.Rel, base)
	r.fixRelaArray(r.Rela, base)
	r.fixRelArray(r.JmpRel, base)
	r.fixRelaArray(r.JmpRela, base)

	logger.Info("Relocations fixed", "rel", len(r.Rel), "rela", len(r.Rela), "jmprel", len(r.JmpRel), "jmprela", len(r.JmpRela))
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
	rname := readStrtabString(r.File, r.strtabOffset, rsym.St_Name)

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
	logger.Debug("Fixed REL", "type", relocType.Text(), "sym", rname, "final_va", P)
}

// fixSingleRela fixes a single RELA relocation entry
func (r *ElfReader) fixSingleRela(rela *Elf64_Rela, base uint64) {
	relocType := rela.Type()
	relocSym := rela.Sym()
	rsym := r.Symbols[relocSym]
	rname := readStrtabString(r.File, r.strtabOffset, rsym.St_Name)

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
	logger.Debug("Fixed RELA", "type", relocType.Text(), "sym", rname, "final_va", P)
}

// BuildStrtab builds a new string table with all symbol names
func (r *ElfReader) BuildStrtab() error {
	logger.Info("Building new string table")

	if len(r.Symbols) == 0 {
		return r.buildEmptyStrtab()
	}

	return r.buildPopulatedStrtab()
}

// buildEmptyStrtab handles the case with no symbols
func (r *ElfReader) buildEmptyStrtab() error {
	logger.Warn("No symbols to process, building minimal string table")
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

	logger.Info("Built string table", "size", len(r.newStrtab), "null", 1, "local", len(localSymbols), "global", len(globalSymbols), "libs", len(r.neededLibs))
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
		symName := readStrtabString(r.File, r.strtabOffset, sym.St_Name)
		logger.Debug("Processing symbol", "idx", i, "name", symName, "value", sym.St_Value, "bind", sym.stBind().Text(), "type", sym.stType())

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
		// Symbols are sorted by hash bucket. The highest symbol index is in the chain
		// of the non-empty bucket with the highest starting index.
		maxBucketIndex := uint32(0)
		for _, bptr := range buckets {
			if bptr > maxBucketIndex {
				maxBucketIndex = bptr
			}
		}

		if maxBucketIndex == 0 {
			// All buckets are empty
			return uint64(header.Symndx), nil
		}

		// Follow the chain starting at maxBucketIndex
		currentSymIndex := uint64(maxBucketIndex)
		for {
			chainIndex := currentSymIndex - uint64(header.Symndx)
			if _, err := file.Seek(int64(chainsOffset+chainIndex*4), io.SeekStart); err != nil {
				return currentSymIndex, nil
			}

			var chainVal uint32
			if err := binary.Read(file, binary.LittleEndian, &chainVal); err != nil {
				return currentSymIndex, nil
			}

			// Bit 0 = 1 marks the end of the chain (last entry for this hash bucket)
			if (chainVal & 1) != 0 {
				return currentSymIndex + 1, nil
			}
			currentSymIndex++

			// Guard against infinite loop
			if currentSymIndex > 1000000 {
				break
			}
		}

		return currentSymIndex + 1, nil
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
		logger.Warn("Failed to stat file for string reading", "error", err)
		return ""
	}
	fileSize := fileInfo.Size()

	offset := strtabOffset + uint64(nameOffset)
	if offset >= uint64(fileSize) {
		logger.Warn("String offset out of bounds", "offset", offset, "fileSize", fileSize)
		return ""
	}

	// Seek to the string position
	_, err = file.Seek(int64(offset), io.SeekStart)
	if err != nil {
		logger.Warn("Failed to seek to string", "offset", offset, "error", err)
		return ""
	}

	// Read until null terminator or end of file, with reasonable limit
	var result []byte
	buf := make([]byte, 1)
	maxLen := 1024 // Prevent reading extremely long strings

	for len(result) < maxLen {
		_, err := file.Read(buf)
		if err != nil || buf[0] == 0 {
			break
		}
		result = append(result, buf[0])
	}

	if len(result) >= maxLen {
		logger.Warn("String too long, truncated", "maxLen", maxLen)
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

// ResolveMetadata resolves offsets for strings like soname, needed libs, and runpath
func (r *ElfReader) ResolveMetadata() {
	for _, entry := range r.Dyns {
		switch entry.Tag {
		case DT_NEEDED:
			lib := r.readString(uint32(entry.Val))
			if lib != "" {
				r.neededLibs = append(r.neededLibs, lib)
				logger.Info("Dependency found", "lib", lib)
			}
		case DT_SONAME:
			r.soname = r.readString(uint32(entry.Val))
			logger.Info("SONAME", "name", r.soname)
		case DT_RUNPATH:
			r.runpath = r.readString(uint32(entry.Val))
			logger.Info("RUNPATH", "path", r.runpath)
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

// ReadVersioningMetadata reads GNU versioning information if present
func (r *ElfReader) ReadVersioningMetadata() error {
	if r.versymOffset != 0 {
		logger.Info("Found symbol versioning", "vaddr", fmt.Sprintf("0x%x", r.versymOffset))
		// Versym is an array of uint16 indices, one per dynamic symbol
		// We'll just log found for now, but we could read it if we need to fix indices.
	}

	if r.verneedOffset != 0 && r.verneedNum > 0 {
		logger.Info("Reading version requirements", "vaddr", fmt.Sprintf("0x%x", r.verneedOffset), "count", r.verneedNum)
		// Verneed is a linked list of Elf64_Verneed structures
		curr := r.verneedOffset
		for i := uint16(0); i < r.verneedNum; i++ {
			vn, err := readArray[Elf64_Verneed](r.File, curr, 1, "DT_VERNEED")
			if err != nil || len(vn) == 0 {
				break
			}
			file := r.readString(vn[0].File)
			logger.Info("  + required from", "file", file, "aux_count", vn[0].Cnt)

			// Read aux entries
			auxCurr := curr + uint64(vn[0].Aux)
			for j := uint16(0); j < vn[0].Cnt; j++ {
				vna, err := readArray[Elf64_Vernaux](r.File, auxCurr, 1, "DT_VERNAUX")
				if err != nil || len(vna) == 0 {
					break
				}
				name := r.readString(vna[0].Name)
				logger.Debug("    - version", "name", name)
				if vna[0].Next == 0 {
					break
				}
				auxCurr += uint64(vna[0].Next)
			}

			if vn[0].Next == 0 {
				break
			}
			curr += uint64(vn[0].Next)
		}
	}
	return nil
}

// calculateVerneedSize calculates the total size of the verneed section
// by traversing the linked list of Elf64_Verneed and Elf64_Vernaux structures
func (r *ElfReader) calculateVerneedSize() uint64 {
	if r.verneedOffset == 0 || r.verneedNum == 0 {
		return 0
	}

	minAddr := r.verneedOffset
	maxAddr := r.verneedOffset

	// Traverse the verneed linked list to find extent
	curr := r.verneedOffset
	for i := uint16(0); i < r.verneedNum; i++ {
		vn, err := readArray[Elf64_Verneed](r.File, curr, 1, "DT_VERNEED")
		if err != nil || len(vn) == 0 {
			break
		}

		// Update max address to include this Verneed struct
		if curr+uint64(binary.Size(Elf64_Verneed{})) > maxAddr {
			maxAddr = curr + uint64(binary.Size(Elf64_Verneed{}))
		}

		// Traverse aux entries
		auxCurr := curr + uint64(vn[0].Aux)
		for j := uint16(0); j < vn[0].Cnt; j++ {
			vna, err := readArray[Elf64_Vernaux](r.File, auxCurr, 1, "DT_VERNAUX")
			if err != nil || len(vna) == 0 {
				break
			}

			// Update max address to include this Vernaux struct
			if auxCurr+uint64(binary.Size(Elf64_Vernaux{})) > maxAddr {
				maxAddr = auxCurr + uint64(binary.Size(Elf64_Vernaux{}))
			}

			if vna[0].Next == 0 {
				break
			}
			auxCurr += uint64(vna[0].Next)
		}

		if vn[0].Next == 0 {
			break
		}
		curr += uint64(vn[0].Next)
	}

	size := maxAddr - minAddr
	logger.Debug("Calculated verneed size", "start", fmt.Sprintf("0x%x", minAddr), "end", fmt.Sprintf("0x%x", maxAddr), "size", size)
	return size
}
