package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/log"
)

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
	jmprelEntrySize     uint64
	pltRelSz            uint64
	phdrPtLoadPageStart uint64
	symCount            uint64

	// .init_array, .fini_array
	initArrayOffset uint64
	initArraySize   uint64
	finiArrayOffset uint64
	finiArraySize   uint64
	initOffset      uint64 // DT_INIT
	finiOffset      uint64 // DT_FINI

	// .preinit_array
	preinitArrayOffset uint64
	preinitArraySize   uint64

	// .hash and .gnu.hash
	hashOffset    uint64
	hashSize      uint64
	gnuHashOffset uint64
	gnuHashSize   uint64

	// .dynamic section
	dynamicAddr   uint64
	dynamicOffset uint64
	dynamicSize   uint64

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

	// Versioning information
	verneedOffset uint64
	verneedNum    uint16
	verneedSize   uint64
	versymOffset  uint64

	// Dependencies
	neededLibs []string
	soname     string
	runpath    string
	flags      uint64
	flags1     uint64

	// Specialized segments
	tlsOffset uint64

	// GOT information
	gotOffset    uint64
	gotSize      uint64
	pltGotOffset uint64 // from DT_PLTGOT
	pltGotSize   uint64 // calculated from JUMP_SLOTS
	tlsSize      uint64
	relroAddr    uint64
	relroSize    uint64

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

func (r *ElfReader) Read() error {
	// 1. Read and validate ELF header
	if err := r.ReadElfHeader(); err != nil {
		return fmt.Errorf("failed to read elf header: %w", err)
	}

	// 2. Read Program Header Table (PHT)
	if err := r.ReadPhdrs(); err != nil {
		return fmt.Errorf("failed to read program headers: %w", err)
	}

	// 3. Read Dynamic Section (DT)
	if err := r.ReadDyns(); err != nil {
		return fmt.Errorf("failed to read dynamic section: %w", err)
	}

	// 4. Read Relocations (REL/RELA)
	if err := r.ReadRelocs(); err != nil {
		return fmt.Errorf("failed to read relocations: %w", err)
	}

	// 5. Resolve metadata
	r.ResolveMetadata()

	return nil
}

func (r *ElfReader) ReadElfHeader() error {
	logger.Debug("ehdr:read")
	if err := binary.Read(r.File, binary.LittleEndian, r.ElfHeader); err != nil {
		return fmt.Errorf("failed to read ELF header: %w", err)
	}

	// Normalize entry point if it appears absolute
	if r.BaseAddr != 0 && r.ElfHeader.Entry >= r.BaseAddr {
		r.ElfHeader.Entry -= r.BaseAddr
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
	logger.Info("ehdr:valid", "class", "64-bit", "arch", "aarch64", "type", "shared object", "phentsize", r.ElfHeader.Phentsize)

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

	logger.Info("phdr:read", "offset", r.ElfHeader.PhdrOffset, "count", r.ElfHeader.Phnum)

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

		// Log all program headers with consistent format - Level 3
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("phdr:entry",
				"idx", i,
				"type", phdr.Type.Text(),
				"vaddr", phdr.Vaddr,
				"filesz", phdr.Filesz,
				"memsz", phdr.Memsz,
				"flags", phdr.Flags.Text(),
			)
		}
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
		logger.Warn("dyn:missing", "msg", "missing PT_DYNAMIC")
		return nil
	}

	entryCount := dynamicPhdr.Memsz / uint64(binary.Size(Elf64_Dyn{}))
	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero entries")
	}

	logger.Info("dyn:read", "vaddr", dynamicPhdr.Vaddr, "count", entryCount)

	// Store dynamic section info for rebuilder
	// Vaddr for section address, also used as file offset for memory dumps
	r.dynamicAddr = dynamicPhdr.Vaddr
	r.dynamicOffset = dynamicPhdr.Vaddr // Use Vaddr as offset for memory dumps
	r.dynamicSize = dynamicPhdr.Memsz

	// Read the dynamic section content
	var err error
	if r.Dyns, err = readArray[Elf64_Dyn](r.File, dynamicPhdr.Vaddr, entryCount, "DT_DYNAMIC"); err != nil {
		return err
	}

	// Build map and extract essential fields for rebuilder
	r.dynMap = make(map[DT_Tag]uint64)
	for _, entry := range r.Dyns {
		val := entry.Val

		// Normalize addresses relative to base
		switch entry.Tag {
		case DT_STRTAB, DT_SYMTAB, DT_REL, DT_RELA, DT_JMPREL, DT_HASH, DT_GNU_HASH, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_VERNEED, DT_VERSYM, DT_INIT, DT_FINI, DT_PLTGOT:
			if val >= r.BaseAddr {
				val -= r.BaseAddr
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
		case DT_PLTGOT:
			r.pltGotOffset = val
		case DT_RELA:
			r.relaOffset = val
		case DT_RELASZ:
			r.relaSize = val
		case DT_JMPREL:
			r.jmprelOffset = val
		case DT_PLTREL:
			if val == uint64(DT_REL) {
				r.jmprelEntrySize = uint64(binary.Size(Elf64_Rel{}))
			} else {
				r.jmprelEntrySize = uint64(binary.Size(Elf64_Rela{}))
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
		case DT_STRSZ:
			r.strtabSize = val
		case DT_INIT:
			r.initOffset = val
		case DT_FINI:
			r.finiOffset = val
		case DT_VERNEED:
			r.verneedOffset = val
		case DT_VERNEEDNUM:
			r.verneedNum = uint16(val)
		case DT_VERSYM:
			r.versymOffset = val
		}

		logger.Debug("dyn:entry", "tag", entry.Tag.Text(), "val", val)
		r.dynMap[entry.Tag] = val
	}

	return nil
}

// calculateVerneedSize walks the verneed chain to compute total section size
func (r *ElfReader) calculateVerneedSize() uint64 {
	offset := r.verneedOffset
	totalSize := uint64(0)

	fileInfo, err := r.File.Stat()
	if err != nil {
		return 0
	}
	fileSize := uint64(fileInfo.Size())

	for i := uint16(0); i < r.verneedNum; i++ {
		if offset+16 > fileSize {
			logger.Warn("verneed:bounds", "offset", offset, "filesize", fileSize)
			break
		}

		var verneed Elf64_Verneed
		if _, err := r.File.Seek(int64(offset), io.SeekStart); err != nil {
			break
		}
		if err := binary.Read(r.File, binary.LittleEndian, &verneed); err != nil {
			break
		}

		entrySize := uint64(16) + uint64(verneed.Cnt)*16
		if offset+entrySize > fileSize {
			logger.Warn("verneed:entry_bounds", "offset", offset, "size", entrySize, "filesize", fileSize)
			break
		}
		totalSize += entrySize

		if verneed.Next == 0 {
			break
		}
		offset += uint64(verneed.Next)
	}

	logger.Debug("verneed:calc", "entries", r.verneedNum, "totalSize", totalSize)
	return totalSize
}

func (r *ElfReader) ReadRelocs() error {
	if err := r.readSymbols(); err != nil {
		return err
	}

	return r.readRelocationTables()
}

// readSymbols reads the symbol table
func (r *ElfReader) readSymbols() error {
	var err error
	if r.symCount, err = r.calculateSymbolCount(); err != nil {
		return fmt.Errorf("sym:read | %w", err)
	}

	if r.symCount == 0 {
		logger.Warn("sym:missing", "msg", "none found")
		return nil
	}

	logger.Info("sym:read", "offset", r.symtabOffset, "count", r.symCount)
	if r.Symbols, err = readArray[Elf64_Sym](r.File, r.symtabOffset, r.symCount, "DT_SYMTAB"); err != nil {
		return fmt.Errorf("failed to read symbols: %w", err)
	}

	// Normalize symbol values
	for i := range r.Symbols {
		sym := &r.Symbols[i]
		if r.BaseAddr != 0 && sym.St_Value >= r.BaseAddr {
			sym.St_Value -= r.BaseAddr
		}
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
		// Normalize REL offsets
		for i := range r.Rel {
			if r.BaseAddr != 0 && r.Rel[i].Offset >= r.BaseAddr {
				r.Rel[i].Offset -= r.BaseAddr
			}
		}
	}

	if r.relaOffset != 0 {
		relaCount := r.relaSize / uint64(binary.Size(Elf64_Rela{}))
		logger.Info("rela:read", "offset", r.relaOffset, "count", relaCount)
		if r.Rela, err = readArray[Elf64_Rela](r.File, r.relaOffset, relaCount, "DT_RELA"); err != nil {
			return err
		}
		// Normalize RELA offsets
		for i := range r.Rela {
			if r.BaseAddr != 0 && r.Rela[i].Offset >= r.BaseAddr {
				r.Rela[i].Offset -= r.BaseAddr
			}
		}
	}

	if r.jmprelOffset != 0 {
		switch r.jmprelEntrySize {
		case uint64(binary.Size(Elf64_Rel{})):
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rel{}))
			logger.Info("jmprel:read", "offset", r.jmprelOffset, "count", jmprelCount, "type", "REL")
			if r.JmpRel, err = readArray[Elf64_Rel](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
			// Normalize JMPREL (REL) offsets
			for i := range r.JmpRel {
				if r.BaseAddr != 0 && r.JmpRel[i].Offset >= r.BaseAddr {
					r.JmpRel[i].Offset -= r.BaseAddr
				}
			}
		case uint64(binary.Size(Elf64_Rela{})):
			jmprelCount := r.jmprelSize / uint64(binary.Size(Elf64_Rela{}))
			logger.Info("jmprel:read", "offset", r.jmprelOffset, "count", jmprelCount, "type", "RELA")
			if r.JmpRela, err = readArray[Elf64_Rela](r.File, r.jmprelOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
			// Normalize JMPRELA (RELA) offsets
			for i := range r.JmpRela {
				if r.BaseAddr != 0 && r.JmpRela[i].Offset >= r.BaseAddr {
					r.JmpRela[i].Offset -= r.BaseAddr
				}
			}
		default:
			logger.Error("jmprel:read", "msg", "invalid entry size", "size", r.jmprelEntrySize)
		}
	}

	return nil
}

// calculateSymbolCount determines the total number of symbols using hash tables
func (r *ElfReader) calculateSymbolCount() (uint64, error) {
	// Try .hash table first (simpler, direct symbol count)
	if r.hashOffset != 0 {
		logger.Debug("hash:read", "offset", r.hashOffset)

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
		logger.Debug("gnuhash:read", "offset", r.gnuHashOffset)

		if _, err := r.File.Seek(int64(r.gnuHashOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("gnu_hash:seek | %w", err)
		}

		var header GNUHashHeader
		if err := binary.Read(r.File, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("gnu_hash:read | %w", err)
		}

		// Calculate bloom filter size
		bloomSize := uint64(header.Maskwords) * 8
		bucketsOffset := r.gnuHashOffset + 16 + bloomSize
		chainsOffset := bucketsOffset + uint64(header.Nbuckets)*4

		// Read buckets to find max symbol index
		buckets := make([]uint32, header.Nbuckets)
		if _, err := r.File.Seek(int64(bucketsOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("gnu_hash:buckets_seek | %w", err)
		}
		if err := binary.Read(r.File, binary.LittleEndian, buckets); err != nil {
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

// calculateHashSizes determines the exact size of .hash and .gnu.hash sections
func (r *ElfReader) calculateHashSizes() {
	if r.hashOffset != 0 {
		if _, err := r.File.Seek(int64(r.hashOffset), io.SeekStart); err == nil {
			var header HashHeader
			if err := binary.Read(r.File, binary.LittleEndian, &header); err == nil {
				// size = header (8) + buckets (nbucket * 4) + chains (nchain * 4)
				r.hashSize = 8 + uint64(header.Nbucket)*4 + uint64(header.Nchain)*4
				logger.Debug("hash:calc", "size", r.hashSize)
			}
		}
	}

	if r.gnuHashOffset != 0 {
		if _, err := r.File.Seek(int64(r.gnuHashOffset), io.SeekStart); err == nil {
			var header GNUHashHeader
			if err := binary.Read(r.File, binary.LittleEndian, &header); err == nil {
				// size = header (16) + bloom filter (maskwords * 8) + buckets (nbuckets * 4) + chains
				bloomSize := uint64(header.Maskwords) * 8
				bucketsSize := uint64(header.Nbuckets) * 4
				// We need to know the number of symbols in gnu.hash to find chains size
				// Symbols in gnu.hash = total symbols - symndx
				if r.symCount > uint64(header.Symndx) {
					chainsSize := (r.symCount - uint64(header.Symndx)) * 4
					r.gnuHashSize = 16 + bloomSize + bucketsSize + chainsSize
					logger.Debug("gnuhash:calc", "size", r.gnuHashSize)
				}
			}
		}
	}
}

// ResolveMetadata resolves offsets for strings like soname, needed libs, and runpath
func (r *ElfReader) ResolveMetadata() {
	// Calculate hash sizes
	r.calculateHashSizes()

	// Resolve metadata
	for _, entry := range r.Dyns {
		switch entry.Tag {
		case DT_NEEDED:
			lib := r.readStrtabString(uint32(entry.Val))
			if lib != "" {
				r.neededLibs = append(r.neededLibs, lib)
				logger.Info("lib:needed", "name", lib)
			}
		case DT_SONAME:
			r.soname = r.readStrtabString(uint32(entry.Val))
			logger.Info("soname:read", "name", r.soname)
		case DT_RUNPATH:
			r.runpath = r.readStrtabString(uint32(entry.Val))
			logger.Info("runpath:read", "path", r.runpath)
		}
	}

	// Calculate verneed size if present
	if r.verneedOffset != 0 && r.verneedNum > 0 {
		r.verneedSize = r.calculateVerneedSize()
	}

	// Calculate GOT bounds from relocations
	r.calculateGotBounds()
}

// calculateGotBounds scans relocations to determine .got size and range
func (r *ElfReader) calculateGotBounds() {
	minGot := ^uint64(0)
	maxGot := uint64(0)
	found := false

	// Scan symbols/relocs for GLOB_DAT (which populate the .got)
	scanReloc := func(ttype uint32, offset uint64) {
		if RelocationType(ttype) == R_AARCH64_GLOB_DAT {
			if offset < minGot {
				minGot = offset
			}
			if offset > maxGot {
				maxGot = offset
			}
			found = true
		}
	}

	// Scan RELA
	for _, rela := range r.Rela {
		scanReloc(uint32(rela.Info&0xffffffff), rela.Offset)
	}

	// Scan REL
	for _, rel := range r.Rel {
		scanReloc(uint32(rel.Info&0xffffffff), rel.Offset)
	}

	if found {
		r.gotOffset = minGot
		// Size covers from min to max + 8 bytes (ptr size)
		r.gotSize = (maxGot - minGot) + 8
		logger.Debug("got:calc", "start", r.gotOffset, "size", r.gotSize)
	}

	// Calculate .got.plt size if we have PLT relocs
	if r.pltGotOffset != 0 && r.jmprelSize > 0 && r.jmprelEntrySize > 0 {
		// Size = (entries * 8) + 3 reserved entries (24 bytes)
		count := r.jmprelSize / r.jmprelEntrySize
		r.pltGotSize = (count * 8) + 24
		logger.Debug("gotplt:calc", "start", r.pltGotOffset, "size", r.pltGotSize)
	}
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
		logger.Warn("strtab:read | offset out of bounds", "offset", offset, "size", fileInfo.Size())
		return ""
	}

	if _, err = r.File.Seek(int64(offset), io.SeekStart); err != nil {
		logger.Warn("strtab:read | seek failed", "offset", offset, "error", err)
		return ""
	}

	var result []byte
	buf := make([]byte, 1)

	for {
		n, err := r.File.Read(buf)
		if buf[0] == 0 {
			break
		}
		if n == 0 {
			logger.Warn("strtab:read | end of file", "offset", offset)
			break
		}
		if err != nil {
			logger.Warn("strtab:read | read failed", "offset", offset, "error", err)
			break
		}
		result = append(result, buf[0])
	}

	return string(result)
}

// readUint64At reads a uint64 from the source file at the given offset
func (r *ElfReader) readUint64At(offset uint64) uint64 {
	if _, err := r.File.Seek(int64(offset), io.SeekStart); err != nil {
		logger.Warn("uint64:read", "msg", "seek failed", "offset", offset, "error", err)
		return 0
	}
	var val uint64
	if err := binary.Read(r.File, binary.LittleEndian, &val); err != nil {
		logger.Warn("uint64:read", "msg", "read failed", "offset", offset, "error", err)
		return 0
	}
	return val
}
