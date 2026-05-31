package sofixer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/log"
)

type ElfReader struct {
	File        *os.File
	ElfHeader   *Elf64_Ehdr
	Phdrs       []Elf64_Phdr
	Dyns        []Elf64_Dyn
	Rel         []Elf64_Rel
	Rela        []Elf64_Rela
	Relr        []uint64
	AndroidRel  []Elf64_Rel
	AndroidRela []Elf64_Rela
	JmpRel      []Elf64_Rel
	JmpRela     []Elf64_Rela
	Symbols     []Elf64_Sym

	logger *log.Logger

	strtabVaddr      uint64
	symtabVaddr      uint64
	relVaddr         uint64
	relSize          uint64
	relaVaddr        uint64
	relaSize         uint64
	relrVaddr        uint64
	relrSize         uint64
	androidRelVaddr  uint64
	androidRelSize   uint64
	androidRelaVaddr uint64
	androidRelaSize  uint64
	jmprelVaddr      uint64
	jmprelSize       uint64
	jmprelEntrySize  uint64
	symCount         uint64

	// .init_array, .fini_array
	initArrayVaddr uint64
	initArraySize  uint64
	finiArrayVaddr uint64
	finiArraySize  uint64

	// .preinit_array
	preinitArrayVaddr uint64
	preinitArraySize  uint64

	// .hash and .gnu.hash
	hashVaddr    uint64
	hashSize     uint64
	gnuHashVaddr uint64
	gnuHashSize  uint64

	// .dynamic section
	dynamicVaddr uint64
	dynamicSize  uint64

	// PT_GNU_EH_FRAME (.eh_frame_hdr)
	ehFrameHdrVaddr uint64
	ehFrameHdrSize  uint64

	// PT_NOTE (.note.gnu.build-id)
	noteVaddr uint64
	noteSize  uint64

	// Versioning information
	verneedVaddr uint64
	verneedNum   uint16
	verneedSize  uint64
	versymVaddr  uint64

	// Dependencies
	neededLibs []string
	soname     string
	runpath    string

	// GOT information
	gotVaddr    uint64
	gotSize     uint64
	pltGotVaddr uint64 // from DT_PLTGOT
	pltGotSize  uint64 // calculated from JUMP_SLOTS

	// .strtab size
	strtabSize uint64

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
	r.logger.Debug("ehdr read")
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
	if r.ElfHeader.Version != 1 || r.ElfHeader.Version2 != 1 {
		return fmt.Errorf("invalid ELF version: e_ident[EI_VERSION]=%d e_version=%d (expected 1)",
			r.ElfHeader.Version, r.ElfHeader.Version2)
	}
	if r.ElfHeader.Ehsize != sizeofEhdr {
		return fmt.Errorf("invalid ELF header size: %d (expected %d)", r.ElfHeader.Ehsize, sizeofEhdr)
	}
	if r.ElfHeader.Phentsize != sizeofPhdr {
		return fmt.Errorf("invalid program header entry size: %d (expected %d)", r.ElfHeader.Phentsize, sizeofPhdr)
	}
	if r.ElfHeader.Type != ET_DYN {
		return fmt.Errorf("unsupported ELF type: %d (expected shared object/3)", r.ElfHeader.Type)
	}
	r.logger.Info("ehdr valid", "class", "64-bit", "arch", "aarch64", "type", "shared object", "entry_size", r.ElfHeader.Phentsize)

	return nil
}

func (r *ElfReader) ReadPhdrs() error {
	phtSize := uint64(r.ElfHeader.Phnum) * uint64(r.ElfHeader.Phentsize)
	if phtSize == 0 {
		return fmt.Errorf("phdr read | no program headers found")
	}
	if r.ElfHeader.Phnum > 1024 {
		return fmt.Errorf("phdr read | too many headers: %d (max 1024)", r.ElfHeader.Phnum)
	}

	r.logger.Info("phdr read", "offset", r.ElfHeader.PhdrOffset, "count", r.ElfHeader.Phnum)

	var err error
	if r.Phdrs, err = readArray[Elf64_Phdr](r.logger, r.File, r.ElfHeader.PhdrOffset, uint64(r.ElfHeader.Phnum), "PT_PHDR"); err != nil {
		return err
	}

	for i := range r.Phdrs {
		phdr := &r.Phdrs[i]

		// For memory dumps (linear), ignore the p_offset from the header and use p_vaddr
		if r.BaseAddr != 0 {
			if phdr.Vaddr >= r.BaseAddr {
				phdr.Vaddr -= r.BaseAddr
			}
			// Force Offset to match Vaddr for reading from linear dump
			phdr.Offset = phdr.Vaddr
		}

		// Extract metadata from program headers
		switch phdr.Type {
		case PT_GNU_EH_FRAME:
			r.ehFrameHdrVaddr = phdr.Vaddr
			r.ehFrameHdrSize = phdr.Memsz
		case PT_NOTE:
			r.noteVaddr = phdr.Vaddr
			r.noteSize = phdr.Memsz
		}

		// Per ELF spec, p_align must be 0, 1, or a power of two. Bad values
		// usually mean the PHT itself is corrupt — warn but proceed.
		if a := phdr.Align; a > 1 && a&(a-1) != 0 {
			r.logger.Warn("phdr align", "reason", "not power of two", "index", i, "align", a)
		}

		// Log all program headers with consistent format - Level 3
		if r.logger.GetLevel() == log.DebugLevel {
			r.logger.Debug("phdr entry",
				"index", i,
				"type", phdr.Type.Text(),
				"vaddr", phdr.Vaddr,
				"file_size", phdr.Filesz,
				"memory_size", phdr.Memsz,
				"flags", phdr.Flags.Text(),
			)
		}
	}

	return nil
}

// vaddrToOffset maps a virtual address into a file offset using PT_LOAD ranges.
// For inputs that don't fall in any PT_LOAD (corrupt dumps), it returns the vaddr
// unchanged — this is the linear-dump fallback. Logged at Debug so misses are visible.
func (r *ElfReader) vaddrToOffset(vaddr uint64) uint64 {
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD {
			if vaddr >= phdr.Vaddr && vaddr < phdr.Vaddr+phdr.Memsz {
				return phdr.Offset + (vaddr - phdr.Vaddr)
			}
		}
	}
	r.logger.Debug("vaddr fallback", "reason", "no PT_LOAD match", "vaddr", vaddr)
	return vaddr
}

func (r *ElfReader) ReadDyns() error {
	var dynamicPhdr *Elf64_Phdr
	for i := range r.Phdrs {
		if r.Phdrs[i].Type == PT_DYNAMIC {
			dynamicPhdr = &r.Phdrs[i]
			break
		}
	}

	if dynamicPhdr == nil {
		// No PT_DYNAMIC means a stripped/unusual dump; we can't recover
		// relocation/symbol metadata, so continue with what we have.
		r.logger.Warn("dyn missing", "detail", "missing pt_dynamic")
		return nil
	}

	// Ensure dynamic section data is sizable
	if dynamicPhdr.Memsz == 0 {
		// Some dumps have PT_DYNAMIC with zero size — use p_filesz if available
		if dynamicPhdr.Filesz > 0 {
			dynamicPhdr.Memsz = dynamicPhdr.Filesz
		} else {
			r.logger.Warn("dyn empty", "detail", "pt_dynamic has zero size")
			return nil
		}
	}

	entryCount := dynamicPhdr.Memsz / uint64(sizeofDyn)
	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero entries")
	}

	r.logger.Info("dyn read", "vaddr", dynamicPhdr.Vaddr, "count", entryCount)

	// Store dynamic section info for rebuilder. Memory dumps are linear, so we
	// reuse the virtual address as the file offset.
	r.dynamicVaddr = dynamicPhdr.Vaddr
	r.dynamicSize = dynamicPhdr.Memsz

	// Read the dynamic section content
	var err error
	if r.Dyns, err = readArray[Elf64_Dyn](r.logger, r.File, r.dynamicVaddr, entryCount, "DT_DYNAMIC"); err != nil {
		return err
	}

	for i := range r.Dyns {
		entry := &r.Dyns[i]
		// DT_NULL terminates the dynamic array; anything past it is undefined
		// (in dumps, often stale runtime data that can resemble real tags).
		if entry.Tag == DT_NULL {
			break
		}
		val := entry.Val

		// Normalize addresses relative to base
		switch entry.Tag {
		case DT_STRTAB, DT_SYMTAB, DT_REL, DT_RELA, DT_JMPREL, DT_HASH, DT_GNU_HASH, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_PREINIT_ARRAY, DT_VERNEED, DT_VERSYM, DT_INIT, DT_FINI, DT_PLTGOT, DT_ANDROID_REL, DT_ANDROID_RELA, DT_RELR:
			if val >= r.BaseAddr {
				val -= r.BaseAddr
			}
		}

		// Write back normalized value to Dyns for later serialization
		entry.Val = val

		// Only extract fields actually used by the rebuilder
		switch entry.Tag {
		case DT_STRTAB:
			r.strtabVaddr = val
		case DT_SYMTAB:
			r.symtabVaddr = val
		case DT_HASH:
			r.hashVaddr = val
		case DT_GNU_HASH:
			r.gnuHashVaddr = val
		case DT_REL:
			r.relVaddr = val
		case DT_RELSZ:
			r.relSize = val
		case DT_PLTGOT:
			r.pltGotVaddr = val
		case DT_RELA:
			r.relaVaddr = val
		case DT_RELASZ:
			r.relaSize = val
		case DT_ANDROID_RELA:
			r.androidRelaVaddr = val
		case DT_ANDROID_RELASZ:
			r.androidRelaSize = val
		case DT_ANDROID_REL:
			r.androidRelVaddr = val
		case DT_ANDROID_RELSZ:
			r.androidRelSize = val
		case DT_RELR:
			r.relrVaddr = val
		case DT_RELRSZ:
			r.relrSize = val
		case DT_JMPREL:
			r.jmprelVaddr = val
		case DT_PLTREL:
			if val == uint64(DT_REL) {
				r.jmprelEntrySize = uint64(sizeofRel)
			} else {
				r.jmprelEntrySize = uint64(sizeofRela)
			}
		case DT_PLTRELSZ:
			r.jmprelSize = val
		case DT_INIT_ARRAY:
			r.initArrayVaddr = val
		case DT_INIT_ARRAYSZ:
			r.initArraySize = val
		case DT_FINI_ARRAY:
			r.finiArrayVaddr = val
		case DT_FINI_ARRAYSZ:
			r.finiArraySize = val
		case DT_PREINIT_ARRAY:
			r.preinitArrayVaddr = val
		case DT_PREINIT_ARRAYSZ:
			r.preinitArraySize = val
		case DT_STRSZ:
			r.strtabSize = val
		case DT_VERNEED:
			r.verneedVaddr = val
		case DT_VERNEEDNUM:
			r.verneedNum = uint16(val)
		case DT_VERSYM:
			r.versymVaddr = val
		}

		r.logger.Debug("dyn entry", "tag", entry.Tag.Text(), "value", val)
	}

	return nil
}

// calculateVerneedSize walks the verneed chain to compute total section size
func (r *ElfReader) calculateVerneedSize() uint64 {
	offset := r.verneedVaddr
	totalSize := uint64(0)

	fileInfo, err := r.File.Stat()
	if err != nil {
		return 0
	}
	fileSize := uint64(fileInfo.Size())

	for i := uint16(0); i < r.verneedNum; i++ {
		fileOffset := r.vaddrToOffset(offset)
		if fileOffset+sizeofVerneed > fileSize {
			r.logger.Warn("verneed bounds", "offset", fileOffset, "file_size", fileSize)
			break
		}

		var verneed Elf64_Verneed
		if _, err := r.File.Seek(int64(fileOffset), io.SeekStart); err != nil {
			break
		}
		if err := binary.Read(r.File, binary.LittleEndian, &verneed); err != nil {
			break
		}

		entrySize := uint64(sizeofVerneed) + uint64(verneed.Cnt)*sizeofVernaux
		if fileOffset+entrySize > fileSize {
			r.logger.Warn("verneed entry_bounds", "offset", fileOffset, "size", entrySize, "file_size", fileSize)
			break
		}
		totalSize += entrySize

		if verneed.Next == 0 {
			break
		}
		offset += uint64(verneed.Next)
	}

	r.logger.Debug("verneed calc", "entries", r.verneedNum, "total_size", totalSize)
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
		r.logger.Warn("sym missing", "detail", "none found")
		return nil
	}

	r.logger.Info("sym read", "vaddr", r.symtabVaddr, "count", r.symCount)
	fileOffset := r.vaddrToOffset(r.symtabVaddr)
	if r.Symbols, err = readArray[Elf64_Sym](r.logger, r.File, fileOffset, r.symCount, "DT_SYMTAB"); err != nil {
		return fmt.Errorf("failed to read symbols: %w", err)
	}

	// Normalize symbol values
	for i := range r.Symbols {
		sym := &r.Symbols[i]
		// TLS symbols have st_value relative to TLS block, not vaddr — skip normalization
		if r.BaseAddr != 0 && sym.St_Value >= r.BaseAddr && sym.StType() != STT_TLS {
			sym.St_Value -= r.BaseAddr
		}
	}

	return nil
}

// readRelocationTables reads all relocation tables (REL, RELA, JMPREL)
func (r *ElfReader) readRelocationTables() error {
	var err error

	if r.relVaddr != 0 {
		relCount := r.relSize / uint64(sizeofRel)
		fileOffset := r.vaddrToOffset(r.relVaddr)
		r.logger.Info("rel read", "vaddr", r.relVaddr, "count", relCount)
		if r.Rel, err = readArray[Elf64_Rel](r.logger, r.File, fileOffset, relCount, "DT_REL"); err != nil {
			return err
		}
		// Normalize REL offsets
		for i := range r.Rel {
			if r.BaseAddr != 0 && r.Rel[i].Offset >= r.BaseAddr {
				r.Rel[i].Offset -= r.BaseAddr
			}
		}
	}

	if r.relaVaddr != 0 {
		relaCount := r.relaSize / uint64(sizeofRela)
		fileOffset := r.vaddrToOffset(r.relaVaddr)
		r.logger.Info("rela read", "vaddr", r.relaVaddr, "count", relaCount)
		if r.Rela, err = readArray[Elf64_Rela](r.logger, r.File, fileOffset, relaCount, "DT_RELA"); err != nil {
			return err
		}
		// Normalize RELA offsets
		for i := range r.Rela {
			if r.BaseAddr != 0 && r.Rela[i].Offset >= r.BaseAddr {
				r.Rela[i].Offset -= r.BaseAddr
			}
		}
	}

	if r.androidRelVaddr != 0 && r.androidRelSize > 0 {
		fileOffset := r.vaddrToOffset(r.androidRelVaddr)
		var err2 error
		r.AndroidRel, err2 = r.decodePackedRel(fileOffset, r.androidRelSize)
		if err2 != nil {
			r.logger.Warn("android_rel decode", "error", err2)
		} else {
			r.logger.Info("android_rel read", "vaddr", r.androidRelVaddr, "decoded_count", len(r.AndroidRel))
		}
	}

	if r.androidRelaVaddr != 0 && r.androidRelaSize > 0 {
		fileOffset := r.vaddrToOffset(r.androidRelaVaddr)
		var err2 error
		r.AndroidRela, err2 = r.decodePackedRela(fileOffset, r.androidRelaSize)
		if err2 != nil {
			r.logger.Warn("android_rela decode", "error", err2)
		} else {
			r.logger.Info("android_rela read", "vaddr", r.androidRelaVaddr, "decoded_count", len(r.AndroidRela))
		}
	}

	if r.relrVaddr != 0 {
		count := r.relrSize / 8
		fileOffset := r.vaddrToOffset(r.relrVaddr)
		r.logger.Info("relr read", "vaddr", r.relrVaddr, "count", count)
		if r.Relr, err = readArray[uint64](r.logger, r.File, fileOffset, count, "DT_RELR"); err != nil {
			return err
		}
	}

	if r.jmprelVaddr != 0 {
		if r.jmprelEntrySize == 0 {
			r.jmprelEntrySize = uint64(sizeofRela)
			r.logger.Warn("jmprel default", "detail", "dt_pltrel missing, assuming rela")
		}
		fileOffset := r.vaddrToOffset(r.jmprelVaddr)
		switch r.jmprelEntrySize {
		case uint64(sizeofRel):
			jmprelCount := r.jmprelSize / uint64(sizeofRel)
			r.logger.Info("jmprel read", "vaddr", r.jmprelVaddr, "count", jmprelCount, "type", "rel")
			if r.JmpRel, err = readArray[Elf64_Rel](r.logger, r.File, fileOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
			// Normalize JMPREL (REL) offsets
			for i := range r.JmpRel {
				if r.BaseAddr != 0 && r.JmpRel[i].Offset >= r.BaseAddr {
					r.JmpRel[i].Offset -= r.BaseAddr
				}
			}
		case uint64(sizeofRela):
			jmprelCount := r.jmprelSize / uint64(sizeofRela)
			r.logger.Info("jmprel read", "vaddr", r.jmprelVaddr, "count", jmprelCount, "type", "rela")
			if r.JmpRela, err = readArray[Elf64_Rela](r.logger, r.File, fileOffset, jmprelCount, "DT_JMPRELA"); err != nil {
				return err
			}
			// Normalize JMPRELA (RELA) offsets
			for i := range r.JmpRela {
				if r.BaseAddr != 0 && r.JmpRela[i].Offset >= r.BaseAddr {
					r.JmpRela[i].Offset -= r.BaseAddr
				}
			}
		}
	}

	return nil
}

// calculateSymbolCount determines the total number of symbols using hash tables
func (r *ElfReader) calculateSymbolCount() (uint64, error) {
	// Try standard .hash table first
	if r.hashVaddr != 0 {
		fileOffset := r.vaddrToOffset(r.hashVaddr)
		if _, err := r.File.Seek(int64(fileOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("hash:seek | %w", err)
		}

		var header HashHeader
		if err := binary.Read(r.File, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("hash:read | %w", err)
		}

		return uint64(header.Nchain), nil
	}

	// Fall back to .gnu.hash table
	if r.gnuHashVaddr != 0 {
		fileOffset := r.vaddrToOffset(r.gnuHashVaddr)
		r.logger.Debug("gnuhash read", "vaddr", r.gnuHashVaddr, "offset", fileOffset)

		if _, err := r.File.Seek(int64(fileOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("gnu_hash:seek | %w", err)
		}

		var header GNUHashHeader
		if err := binary.Read(r.File, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("gnu_hash:read | %w", err)
		}

		// Guard against corrupt headers that would allocate excessive memory
		if header.Nbuckets > 65536 || header.Maskwords > 65536 {
			return 0, fmt.Errorf("gnu_hash:corrupt nbuckets=%d maskwords=%d", header.Nbuckets, header.Maskwords)
		}

		// Calculate bloom filter size
		bloomSize := uint64(header.Maskwords) * 8
		bucketsAddr := r.gnuHashVaddr + sizeofGNUHash + bloomSize
		chainsAddr := bucketsAddr + uint64(header.Nbuckets)*4

		// Read buckets
		buckets := make([]uint32, header.Nbuckets)
		if _, err := r.File.Seek(int64(r.vaddrToOffset(bucketsAddr)), io.SeekStart); err != nil {
			return 0, fmt.Errorf("gnu_hash:buckets_seek | %w", err)
		}
		if err := binary.Read(r.File, binary.LittleEndian, buckets); err != nil {
			return 0, fmt.Errorf("gnu_hash:buckets_read | %w", err)
		}

		// Scan ALL non-zero bucket chains to find the true maximum symbol index.
		// A bucket with a lower starting index can have a longer chain that extends
		// past the highest bucket's starting index.
		maxSymIdx := uint64(header.Symndx)
		seenBuckets := make(map[uint32]bool)

		for _, bptr := range buckets {
			if bptr == 0 || seenBuckets[bptr] {
				continue
			}
			seenBuckets[bptr] = true

			currentSymIndex := uint64(bptr)
			for currentSymIndex < 1000000 {
				if currentSymIndex > maxSymIdx {
					maxSymIdx = currentSymIndex
				}
				chainIndex := currentSymIndex - uint64(header.Symndx)
				chainFileOffset := r.vaddrToOffset(chainsAddr + chainIndex*4)

				// Bound check: don't read past file
				fileInfo, _ := r.File.Stat()
				if fileInfo != nil && chainFileOffset+4 > uint64(fileInfo.Size()) {
					break
				}

				if _, err := r.File.Seek(int64(chainFileOffset), io.SeekStart); err != nil {
					break
				}
				var chainVal uint32
				if err := binary.Read(r.File, binary.LittleEndian, &chainVal); err != nil {
					break
				}

				// Bit 0 = 1 marks end of chain
				if (chainVal & 1) != 0 {
					currentSymIndex++
					if currentSymIndex > maxSymIdx {
						maxSymIdx = currentSymIndex
					}
					break
				}
				currentSymIndex++
			}
		}

		return maxSymIdx + 1, nil
	}

	return 0, fmt.Errorf("sym:count | missing DT_HASH or DT_GNU_HASH")
}

// calculateHashSizes determines the exact size of .hash and .gnu.hash sections
func (r *ElfReader) calculateHashSizes() {
	if r.hashVaddr != 0 {
		fileOffset := r.vaddrToOffset(r.hashVaddr)
		if _, err := r.File.Seek(int64(fileOffset), io.SeekStart); err == nil {
			var header HashHeader
			if err := binary.Read(r.File, binary.LittleEndian, &header); err == nil {
				// size = header + buckets (nbucket * 4) + chains (nchain * 4)
				r.hashSize = sizeofHashHdr + uint64(header.Nbucket)*4 + uint64(header.Nchain)*4
				r.logger.Debug("hash calc", "size", r.hashSize)
			}
		}
	}

	if r.gnuHashVaddr != 0 {
		fileOffset := r.vaddrToOffset(r.gnuHashVaddr)
		if _, err := r.File.Seek(int64(fileOffset), io.SeekStart); err == nil {
			var header GNUHashHeader
			if err := binary.Read(r.File, binary.LittleEndian, &header); err == nil {
				// size = header + bloom filter (maskwords * 8) + buckets (nbuckets * 4) + chains
				bloomSize := uint64(header.Maskwords) * 8
				bucketsSize := uint64(header.Nbuckets) * 4
				// Symbols covered by gnu.hash = total symbols - symndx.
				if r.symCount > uint64(header.Symndx) {
					chainsSize := (r.symCount - uint64(header.Symndx)) * 4
					r.gnuHashSize = sizeofGNUHash + bloomSize + bucketsSize + chainsSize
					r.logger.Debug("gnuhash calc", "size", r.gnuHashSize)
				}
			}
		}
	}
}

// ResolveMetadata resolves offsets for strings like soname, needed libs, and runpath
func (r *ElfReader) ResolveMetadata() {
	// Calculate hash sizes
	r.calculateHashSizes()

	// Resolve metadata. DT_RPATH is the older spelling of DT_RUNPATH; we treat
	// it equivalently — some legacy / Android-packer binaries still emit it.
	for _, entry := range r.Dyns {
		switch entry.Tag {
		case DT_NEEDED:
			lib := r.readStrtabString(uint32(entry.Val))
			if lib != "" {
				r.neededLibs = append(r.neededLibs, lib)
				r.logger.Info("lib needed", "name", lib)
			}
		case DT_SONAME:
			r.soname = r.readStrtabString(uint32(entry.Val))
			r.logger.Info("soname read", "name", r.soname)
		case DT_RUNPATH, DT_RPATH:
			r.runpath = r.readStrtabString(uint32(entry.Val))
			r.logger.Info("runpath read", "tag", entry.Tag.Text(), "path", r.runpath)
		}
	}

	// Calculate verneed size if present
	if r.verneedVaddr != 0 && r.verneedNum > 0 {
		r.verneedSize = r.calculateVerneedSize()
	}

	// Calculate GOT bounds from relocations
	r.calculateGotBounds()
}

// calculateGotBounds scans every relocation table for GLOB_DAT (which populates
// the .got) and derives the section bounds from the lowest/highest target.
// Android-packed binaries carry GLOB_DAT in AndroidRel/AndroidRela rather than
// the classic REL/RELA tables, so all four are scanned.
func (r *ElfReader) calculateGotBounds() {
	minGot := ^uint64(0)
	maxGot := uint64(0)
	found := false

	consider := func(ttype uint32, offset uint64) {
		if RelocationType(ttype) != R_AARCH64_GLOB_DAT {
			return
		}
		if offset < minGot {
			minGot = offset
		}
		if offset > maxGot {
			maxGot = offset
		}
		found = true
	}

	for _, t := range [][]Elf64_Rela{r.Rela, r.AndroidRela, r.JmpRela} {
		for _, rela := range t {
			consider(uint32(rela.Info), rela.Offset)
		}
	}
	for _, t := range [][]Elf64_Rel{r.Rel, r.AndroidRel, r.JmpRel} {
		for _, rel := range t {
			consider(uint32(rel.Info), rel.Offset)
		}
	}

	if found {
		r.gotVaddr = minGot
		// Size covers from min to max + 8 bytes (ptr size)
		r.gotSize = (maxGot - minGot) + 8
		r.logger.Debug("got calc", "start", r.gotVaddr, "size", r.gotSize)
	}

	// Calculate .got.plt size if we have PLT relocs
	if r.pltGotVaddr != 0 && r.jmprelSize > 0 && r.jmprelEntrySize > 0 {
		// Size = (entries * 8) + 3 reserved entries (24 bytes)
		count := r.jmprelSize / r.jmprelEntrySize
		r.pltGotSize = (count * 8) + 24
		r.logger.Debug("gotplt calc", "start", r.pltGotVaddr, "size", r.pltGotSize)
	}
}

// readStrtabString reads a null-terminated string from the string table at the
// given name offset. A single ReadAt is used (rather than byte-by-byte) since
// symbol-name reads dominate the demangle hot path.
func (r *ElfReader) readStrtabString(nameOffset uint32) string {
	if nameOffset == 0 || r.strtabVaddr == 0 {
		return ""
	}

	fileOffset := r.vaddrToOffset(r.strtabVaddr + uint64(nameOffset))

	fileInfo, err := r.File.Stat()
	if err != nil {
		r.logger.Warn("strtab read", "reason", "stat failed", "error", err)
		return ""
	}

	fileSize := uint64(fileInfo.Size())
	if fileOffset >= fileSize {
		r.logger.Warn("strtab read", "reason", "offset out of bounds", "offset", fileOffset, "file_size", fileSize)
		return ""
	}

	// Bound the read to strtabSize (or 64 KiB) to guard against missing NULs
	// in corrupted strtab data.
	maxLen := r.strtabSize
	if maxLen == 0 || maxLen > 65536 {
		maxLen = 65536
	}
	remaining := fileSize - fileOffset
	if maxLen > remaining {
		maxLen = remaining
	}

	buf := make([]byte, maxLen)
	n, err := r.File.ReadAt(buf, int64(fileOffset))
	if err != nil && err != io.EOF {
		r.logger.Warn("strtab read", "reason", "read failed", "offset", fileOffset, "error", err)
		return ""
	}
	buf = buf[:n]
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf)
}

// decodePackedRela decodes APS2/APA1 packed relocations (DT_ANDROID_RELA) into Elf64_Rela entries.
// Format: 4-byte magic ("APS2" or "APA1"), then SLEB128-encoded relocation data.
func (r *ElfReader) decodePackedRela(fileOffset uint64, size uint64) ([]Elf64_Rela, error) {
	buf, err := r.readBoundedBlob(fileOffset, size, "android_rela")
	if err != nil {
		return nil, err
	}

	// Check magic header
	if len(buf) < 4 {
		return nil, fmt.Errorf("android_rela:too_short size=%d", len(buf))
	}
	magic := string(buf[:4])
	if magic != "APS2" && magic != "APA1" {
		return nil, fmt.Errorf("android_rela:bad_magic got=%q", magic)
	}

	pos := 4
	var result []Elf64_Rela

	if magic == "APA1" {
		// APA1 format: pairs count, then (offset_delta, addend_delta) pairs
		pairs, n := DecodeSLEB128(buf[pos:])
		pos += n
		if pairs < 0 || uint64(pairs) > uint64(len(buf)) {
			return nil, fmt.Errorf("android_rela:bad_pairs pairs=%d buf=%d", pairs, len(buf))
		}
		var offset, addend int64
		for i := int64(0); i < pairs; i++ {
			odelta, n1 := DecodeSLEB128(buf[pos:])
			pos += n1
			adelta, n2 := DecodeSLEB128(buf[pos:])
			pos += n2
			offset += odelta
			addend += adelta

			rela := Elf64_Rela{
				Offset: uint64(offset),
				Info:   uint64(R_AARCH64_RELATIVE),
				Addend: addend,
			}
			if r.BaseAddr != 0 && rela.Offset >= r.BaseAddr {
				rela.Offset -= r.BaseAddr
			}
			result = append(result, rela)
		}
	} else {
		// APS2 format: count, initial_offset, then grouped relocations
		relocCount, n := DecodeSLEB128(buf[pos:])
		pos += n
		if relocCount < 0 || uint64(relocCount) > uint64(len(buf)) {
			return nil, fmt.Errorf("android_rela:bad_count count=%d buf=%d", relocCount, len(buf))
		}

		// BUGFIX: Read initial offset after count (was previously skipped)
		initialOffset, n := DecodeSLEB128(buf[pos:])
		pos += n
		var offset int64 = initialOffset
		var addend int64

		const (
			groupedByInfo        = 1 // RELOCATION_GROUPED_BY_INFO_FLAG
			groupedByOffsetDelta = 2 // RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG
			groupedByAddend      = 4 // RELOCATION_GROUPED_BY_ADDEND_FLAG
			groupHasAddend       = 8 // RELOCATION_GROUP_HAS_ADDEND_FLAG
		)

		for len(result) < int(relocCount) && pos < len(buf) {
			// Read group header
			groupSize, n1 := DecodeSLEB128(buf[pos:])
			pos += n1
			groupFlags, n2 := DecodeSLEB128(buf[pos:])
			pos += n2

			// Read group-level shared values
			var groupOffsetDelta int64
			if (groupFlags & groupedByOffsetDelta) != 0 {
				groupOffsetDelta, n = DecodeSLEB128(buf[pos:])
				pos += n
			}

			var groupInfo int64
			if (groupFlags & groupedByInfo) != 0 {
				groupInfo, n = DecodeSLEB128(buf[pos:])
				pos += n
			}

			// BUGFIX: Only read addend when groupHasAddend flag is set.
			// If flag 8 is clear, entries have NO addends at all.
			entriesHaveAddends := (groupFlags & groupHasAddend) != 0

			if entriesHaveAddends {
				if (groupFlags & groupedByAddend) != 0 {
					// All entries share the same addend
					groupAddend, n := DecodeSLEB128(buf[pos:])
					pos += n
					addend = groupAddend
				} else {
					// No group addend; per-entry deltas starting from 0
					addend = 0
				}
			} else {
				addend = 0
			}

			// Emit entries within this group
			for i := int64(0); i < groupSize && pos < len(buf); i++ {
				var entryOffsetDelta int64
				if (groupFlags & groupedByOffsetDelta) != 0 {
					entryOffsetDelta = groupOffsetDelta
				} else {
					entryOffsetDelta, n = DecodeSLEB128(buf[pos:])
					pos += n
				}
				offset += entryOffsetDelta

				var entryInfo int64
				if (groupFlags & groupedByInfo) != 0 {
					entryInfo = groupInfo
				} else {
					entryInfo, n = DecodeSLEB128(buf[pos:])
					pos += n
				}

				if entriesHaveAddends && (groupFlags&groupedByAddend) == 0 {
					var addendDelta int64
					addendDelta, n = DecodeSLEB128(buf[pos:])
					pos += n
					addend += addendDelta
				}

				rela := Elf64_Rela{
					Offset: uint64(offset),
					Info:   uint64(entryInfo),
					Addend: addend,
				}
				if r.BaseAddr != 0 && rela.Offset >= r.BaseAddr {
					rela.Offset -= r.BaseAddr
				}
				result = append(result, rela)
			}
		}
	}

	return result, nil
}

// decodePackedRel decodes APS2/APR1 packed relocations (DT_ANDROID_REL) into Elf64_Rel entries.
func (r *ElfReader) decodePackedRel(fileOffset uint64, size uint64) ([]Elf64_Rel, error) {
	buf, err := r.readBoundedBlob(fileOffset, size, "android_rel")
	if err != nil {
		return nil, err
	}

	if len(buf) < 4 {
		return nil, fmt.Errorf("android_rel:too_short size=%d", len(buf))
	}
	magic := string(buf[:4])
	if magic != "APS2" && magic != "APR1" {
		return nil, fmt.Errorf("android_rel:bad_magic got=%q", magic)
	}

	pos := 4
	var result []Elf64_Rel

	if magic == "APR1" {
		// APR1: initial offset, then (count, delta) pairs
		pairs, n := DecodeSLEB128(buf[pos:])
		pos += n
		if pairs < 0 || uint64(pairs) > uint64(len(buf)) {
			return nil, fmt.Errorf("android_rel:bad_pairs pairs=%d buf=%d", pairs, len(buf))
		}
		addr, n2 := DecodeSLEB128(buf[pos:])
		pos += n2

		// Emit first relocation
		rel := Elf64_Rel{Offset: uint64(addr), Info: uint64(R_AARCH64_RELATIVE)}
		if r.BaseAddr != 0 && rel.Offset >= r.BaseAddr {
			rel.Offset -= r.BaseAddr
		}
		result = append(result, rel)

		for i := int64(0); i < pairs; i++ {
			count, n1 := DecodeSLEB128(buf[pos:])
			pos += n1
			delta, n3 := DecodeSLEB128(buf[pos:])
			pos += n3
			if count < 0 || uint64(count) > uint64(len(buf)) {
				return nil, fmt.Errorf("android_rel:bad_pair_count count=%d buf=%d", count, len(buf))
			}
			for j := int64(0); j < count; j++ {
				addr += delta
				rel := Elf64_Rel{Offset: uint64(addr), Info: uint64(R_AARCH64_RELATIVE)}
				if r.BaseAddr != 0 && rel.Offset >= r.BaseAddr {
					rel.Offset -= r.BaseAddr
				}
				result = append(result, rel)
			}
		}
	} else {
		// APS2: count, initial_offset, then grouped relocations (no addends)
		relocCount, n := DecodeSLEB128(buf[pos:])
		pos += n
		if relocCount < 0 || uint64(relocCount) > uint64(len(buf)) {
			return nil, fmt.Errorf("android_rel:bad_count count=%d buf=%d", relocCount, len(buf))
		}

		// BUGFIX: Read initial offset after count (was previously skipped)
		initialOffset, n := DecodeSLEB128(buf[pos:])
		pos += n
		var offset int64 = initialOffset

		const (
			groupedByInfo        = 1 // RELOCATION_GROUPED_BY_INFO_FLAG
			groupedByOffsetDelta = 2 // RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG
		)

		for len(result) < int(relocCount) && pos < len(buf) {
			groupSize, n1 := DecodeSLEB128(buf[pos:])
			pos += n1
			groupFlags, n2 := DecodeSLEB128(buf[pos:])
			pos += n2

			var groupOffsetDelta int64
			if (groupFlags & groupedByOffsetDelta) != 0 {
				groupOffsetDelta, n = DecodeSLEB128(buf[pos:])
				pos += n
			}

			var groupInfo int64
			if (groupFlags & groupedByInfo) != 0 {
				groupInfo, n = DecodeSLEB128(buf[pos:])
				pos += n
			}

			for i := int64(0); i < groupSize && pos < len(buf); i++ {
				var entryOffsetDelta int64
				if (groupFlags & groupedByOffsetDelta) != 0 {
					entryOffsetDelta = groupOffsetDelta
				} else {
					entryOffsetDelta, n = DecodeSLEB128(buf[pos:])
					pos += n
				}
				offset += entryOffsetDelta

				var entryInfo int64
				if (groupFlags & groupedByInfo) != 0 {
					entryInfo = groupInfo
				} else {
					entryInfo, n = DecodeSLEB128(buf[pos:])
					pos += n
				}

				rel := Elf64_Rel{Offset: uint64(offset), Info: uint64(entryInfo)}
				if r.BaseAddr != 0 && rel.Offset >= r.BaseAddr {
					rel.Offset -= r.BaseAddr
				}
				result = append(result, rel)
			}
		}
	}

	return result, nil
}

// DecodeSLEB128 decodes a signed LEB128 value from buf, returning the value and bytes consumed.
// Bails after 10 bytes (the max needed to encode an int64) to avoid spinning on corrupt input.
func DecodeSLEB128(buf []byte) (int64, int) {
	const maxBytes = 10
	var result int64
	var shift uint
	limit := len(buf)
	if limit > maxBytes {
		limit = maxBytes
	}
	for i := 0; i < limit; i++ {
		b := buf[i]
		if shift < 64 {
			result |= int64(b&0x7f) << shift
		}
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && (b&0x40) != 0 {
				result |= -(1 << shift)
			}
			return result, i + 1
		}
	}
	return result, limit
}

// readBoundedBlob reads `size` bytes at `fileOffset`, clamping `size` to the
// remaining file length to guard against corrupt sizing fields.
func (r *ElfReader) readBoundedBlob(fileOffset uint64, size uint64, name string) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("%s:zero_size", name)
	}
	if info, err := r.File.Stat(); err == nil {
		fileSize := uint64(info.Size())
		if fileOffset >= fileSize {
			return nil, fmt.Errorf("%s:offset_past_eof offset=0x%x file_size=0x%x", name, fileOffset, fileSize)
		}
		remaining := fileSize - fileOffset
		if size > remaining {
			r.logger.Warn("blob clamp", "name", name, "requested", size, "max", remaining)
			size = remaining
		}
	}
	buf := make([]byte, size)
	if _, err := r.File.ReadAt(buf, int64(fileOffset)); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%s:read_raw | %w", name, err)
	}
	return buf, nil
}
