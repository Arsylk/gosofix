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
	relEntrySize     uint64
	relaVaddr        uint64
	relaSize         uint64
	relaEntrySize    uint64
	relrVaddr        uint64
	relrSize         uint64
	relrEntrySize    uint64
	relrSectionType  SHT_Type
	androidRelVaddr  uint64
	androidRelSize   uint64
	androidRelDirty  bool
	androidRelaVaddr uint64
	androidRelaSize  uint64
	androidRelaDirty bool
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
	if r.ElfHeader.Data != ELFDATA2LSB {
		return fmt.Errorf("unsupported ELF data encoding: %d (expected little-endian/1)", r.ElfHeader.Data)
	}
	if r.ElfHeader.Machine != EM_AARCH64 {
		return fmt.Errorf("unsupported architecture: %d (expected AArch64/183)", r.ElfHeader.Machine)
	}
	if r.ElfHeader.IdentVersion != 1 || r.ElfHeader.Version != 1 {
		return fmt.Errorf("invalid ELF version: e_ident[EI_VERSION]=%d e_version=%d (expected 1)",
			r.ElfHeader.IdentVersion, r.ElfHeader.Version)
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
		return fmt.Errorf("phdr read: no program headers found")
	}
	if r.ElfHeader.Phnum > 1024 {
		return fmt.Errorf("phdr read: too many headers: %d (max 1024)", r.ElfHeader.Phnum)
	}

	r.logger.Info("phdr read", "offset", r.ElfHeader.PhdrOffset, "count", r.ElfHeader.Phnum)

	var err error
	if r.Phdrs, err = readArray[Elf64_Phdr](r.File, r.ElfHeader.PhdrOffset, uint64(r.ElfHeader.Phnum), "PT_PHDR"); err != nil {
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
				"type", phdr.Type.String(),
				"vaddr", phdr.Vaddr,
				"file_size", phdr.Filesz,
				"memory_size", phdr.Memsz,
				"flags", phdr.Flags.String(),
			)
		}
	}

	return nil
}

// rebaseInLoad subtracts base from val when val falls inside a PT_LOAD segment's
// runtime range [base+vaddr, base+vaddr+memsz). Returns (normalized, true) on a
// hit and (0, false) otherwise. Shared by the reader, rebuilder, and checker so
// the overflow/range guard lives in exactly one place.
func rebaseInLoad(phdrs []Elf64_Phdr, base, val uint64) (uint64, bool) {
	if base == 0 {
		return 0, false
	}
	for _, phdr := range phdrs {
		if phdr.Type != PT_LOAD || phdr.Memsz == 0 {
			continue
		}
		start := base + phdr.Vaddr
		end := start + phdr.Memsz
		if end < start {
			continue
		}
		if val >= start && val < end {
			return val - base, true
		}
	}
	return 0, false
}

// vaddrToFileOffset maps a virtual address into a file offset using PT_LOAD
// ranges, returning (offset, true) on a hit and (0, false) on a miss.
func (r *ElfReader) vaddrToFileOffset(vaddr uint64) (uint64, bool) {
	for _, phdr := range r.Phdrs {
		if phdr.Type != PT_LOAD {
			continue
		}
		if vaddr >= phdr.Vaddr && vaddr < phdr.Vaddr+phdr.Memsz {
			return phdr.Offset + (vaddr - phdr.Vaddr), true
		}
	}
	return 0, false
}

// vaddrToOffset is the linear-dump variant of vaddrToFileOffset: on a miss it
// returns the vaddr unchanged (corrupt dumps are read linearly). Logged at Debug
// so misses are visible.
func (r *ElfReader) vaddrToOffset(vaddr uint64) uint64 {
	if off, ok := r.vaddrToFileOffset(vaddr); ok {
		return off
	}
	r.logger.Debug("vaddr fallback", "reason", "no PT_LOAD match", "vaddr", vaddr)
	return vaddr
}

func (r *ElfReader) normalizeLoadedAddress(val uint64) (uint64, bool) {
	return rebaseInLoad(r.Phdrs, r.BaseAddr, val)
}

func (r *ElfReader) normalizeLoadedAddressValue(val uint64) uint64 {
	if normalized, ok := r.normalizeLoadedAddress(val); ok {
		return normalized
	}
	return val
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
	if dynamicPhdr.Memsz%uint64(sizeofDyn) != 0 {
		return fmt.Errorf("dynamic section size %d is not a multiple of entry size %d", dynamicPhdr.Memsz, sizeofDyn)
	}

	r.logger.Info("dyn read", "vaddr", dynamicPhdr.Vaddr, "count", entryCount)

	// Store dynamic section info for rebuilder. The address is kept as a vaddr;
	// the read uses p_offset so normal ET_DYN files and linear dumps both work.
	r.dynamicVaddr = dynamicPhdr.Vaddr
	r.dynamicSize = dynamicPhdr.Memsz

	// Read the dynamic section content
	var err error
	if r.Dyns, err = readArray[Elf64_Dyn](r.File, dynamicPhdr.Offset, entryCount, "DT_DYNAMIC"); err != nil {
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

		// Normalize address-valued dynamic entries relative to the dump base.
		// Android linear dumps can contain either original relative d_ptr values
		// or runtime-absolute d_ptr values; this conditional handles both forms.
		switch entry.Tag {
		case DT_STRTAB, DT_SYMTAB, DT_REL, DT_RELA, DT_JMPREL,
			DT_HASH, DT_GNU_HASH, DT_INIT_ARRAY, DT_FINI_ARRAY,
			DT_PREINIT_ARRAY, DT_VERNEED, DT_VERSYM, DT_INIT, DT_FINI,
			DT_PLTGOT, DT_ANDROID_REL, DT_ANDROID_RELA, DT_RELR,
			DT_ANDROID_RELR:
			val = r.normalizeLoadedAddressValue(val)
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
		case DT_RELENT:
			r.relEntrySize = val
		case DT_PLTGOT:
			r.pltGotVaddr = val
		case DT_RELA:
			r.relaVaddr = val
		case DT_RELASZ:
			r.relaSize = val
		case DT_RELAENT:
			r.relaEntrySize = val
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
			r.relrSectionType = SHT_RELR
		case DT_ANDROID_RELR:
			r.relrVaddr = val
			r.relrSectionType = SHT_ANDROID_RELR
		case DT_RELRSZ, DT_ANDROID_RELRSZ:
			r.relrSize = val
		case DT_RELRENT, DT_ANDROID_RELRENT:
			r.relrEntrySize = val
		case DT_JMPREL:
			r.jmprelVaddr = val
		case DT_PLTREL:
			switch DT_Tag(val) {
			case DT_REL:
				r.jmprelEntrySize = uint64(sizeofRel)
			case DT_RELA:
				r.jmprelEntrySize = uint64(sizeofRela)
			default:
				return fmt.Errorf("jmprel:unsupported DT_PLTREL tag=%d", val)
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

		r.logger.Debug("dyn entry", "tag", entry.Tag.String(), "value", val)
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

func fixedRelocationEntrySize(name string, got uint64, expected uint64) (uint64, error) {
	if got == 0 {
		return expected, nil
	}
	if got != expected {
		return 0, fmt.Errorf("%s:bad_entry_size got=%d expected=%d", name, got, expected)
	}
	return got, nil
}

func relocationEntryCount(name string, tableSize uint64, entrySize uint64) (uint64, error) {
	if entrySize == 0 {
		return 0, fmt.Errorf("%s:missing_entry_size", name)
	}
	if tableSize%entrySize != 0 {
		return 0, fmt.Errorf("%s:bad_size size=%d entry_size=%d", name, tableSize, entrySize)
	}
	return tableSize / entrySize, nil
}

// readSymbols reads the symbol table
func (r *ElfReader) readSymbols() error {
	var err error
	if r.symCount, err = r.calculateSymbolCount(); err != nil {
		return fmt.Errorf("sym:read: %w", err)
	}

	if r.symCount == 0 {
		r.logger.Warn("sym missing", "detail", "none found")
		return nil
	}

	r.logger.Info("sym read", "vaddr", r.symtabVaddr, "count", r.symCount)
	fileOffset := r.vaddrToOffset(r.symtabVaddr)
	if r.Symbols, err = readArray[Elf64_Sym](r.File, fileOffset, r.symCount, "DT_SYMTAB"); err != nil {
		return fmt.Errorf("failed to read symbols: %w", err)
	}

	// Normalize symbol values
	for i := range r.Symbols {
		sym := &r.Symbols[i]
		// TLS symbols have st_value relative to TLS block, not vaddr — skip normalization
		if sym.StType() != STT_TLS {
			sym.Value = r.normalizeLoadedAddressValue(sym.Value)
		}
	}

	return nil
}

func (r *ElfReader) normalizeRelOffsets(list []Elf64_Rel) {
	for i := range list {
		list[i].Offset = r.normalizeLoadedAddressValue(list[i].Offset)
	}
}

func (r *ElfReader) normalizeRelaOffsets(list []Elf64_Rela) {
	for i := range list {
		list[i].Offset = r.normalizeLoadedAddressValue(list[i].Offset)
	}
}

// readRelocationTables reads all relocation tables (REL, RELA, JMPREL)
func (r *ElfReader) readRelocationTables() error {
	if r.relVaddr != 0 {
		entrySize, err := fixedRelocationEntrySize("DT_REL", r.relEntrySize, uint64(sizeofRel))
		if err != nil {
			return err
		}
		relCount, err := relocationEntryCount("DT_REL", r.relSize, entrySize)
		if err != nil {
			return err
		}
		fileOffset := r.vaddrToOffset(r.relVaddr)
		r.logger.Info("rel read", "vaddr", r.relVaddr, "count", relCount)
		if r.Rel, err = readArray[Elf64_Rel](r.File, fileOffset, relCount, "DT_REL"); err != nil {
			return err
		}
		r.normalizeRelOffsets(r.Rel)
	}

	if r.relaVaddr != 0 {
		entrySize, err := fixedRelocationEntrySize("DT_RELA", r.relaEntrySize, uint64(sizeofRela))
		if err != nil {
			return err
		}
		relaCount, err := relocationEntryCount("DT_RELA", r.relaSize, entrySize)
		if err != nil {
			return err
		}
		fileOffset := r.vaddrToOffset(r.relaVaddr)
		r.logger.Info("rela read", "vaddr", r.relaVaddr, "count", relaCount)
		if r.Rela, err = readArray[Elf64_Rela](r.File, fileOffset, relaCount, "DT_RELA"); err != nil {
			return err
		}
		r.normalizeRelaOffsets(r.Rela)
	}

	if r.androidRelVaddr != 0 && r.androidRelSize > 0 {
		fileOffset := r.vaddrToOffset(r.androidRelVaddr)
		r.androidRelDirty = false
		androidRel, err := r.decodePackedRel(fileOffset, r.androidRelSize)
		if err != nil {
			return fmt.Errorf("android_rel decode: %w", err)
		}
		r.AndroidRel = androidRel
		if r.androidRelDirty {
			return fmt.Errorf("android_rel:dirty_offsets unsupported without packed relocation re-encode")
		}
		r.logger.Info("android_rel read", "vaddr", r.androidRelVaddr, "decoded_count", len(r.AndroidRel))
	}

	if r.androidRelaVaddr != 0 && r.androidRelaSize > 0 {
		fileOffset := r.vaddrToOffset(r.androidRelaVaddr)
		r.androidRelaDirty = false
		androidRela, err := r.decodePackedRela(fileOffset, r.androidRelaSize)
		if err != nil {
			return fmt.Errorf("android_rela decode: %w", err)
		}
		r.AndroidRela = androidRela
		if r.androidRelaDirty {
			return fmt.Errorf("android_rela:dirty_offsets unsupported without packed relocation re-encode")
		}
		r.logger.Info("android_rela read", "vaddr", r.androidRelaVaddr, "decoded_count", len(r.AndroidRela))
	}

	if r.relrVaddr != 0 {
		entrySize, err := fixedRelocationEntrySize("DT_RELR", r.relrEntrySize, sizeofPtr)
		if err != nil {
			return err
		}
		count, err := relocationEntryCount("DT_RELR", r.relrSize, entrySize)
		if err != nil {
			return err
		}
		fileOffset := r.vaddrToOffset(r.relrVaddr)
		r.logger.Info("relr read", "vaddr", r.relrVaddr, "count", count)
		if r.Relr, err = readArray[uint64](r.File, fileOffset, count, "DT_RELR"); err != nil {
			return err
		}
	}

	if r.jmprelVaddr != 0 {
		if r.jmprelEntrySize == 0 {
			return fmt.Errorf("DT_JMPREL:missing_DT_PLTREL")
		}
		fileOffset := r.vaddrToOffset(r.jmprelVaddr)
		switch r.jmprelEntrySize {
		case uint64(sizeofRel):
			jmprelCount, err := relocationEntryCount("DT_JMPREL", r.jmprelSize, uint64(sizeofRel))
			if err != nil {
				return err
			}
			r.logger.Info("jmprel read", "vaddr", r.jmprelVaddr, "count", jmprelCount, "type", "rel")
			if r.JmpRel, err = readArray[Elf64_Rel](r.File, fileOffset, jmprelCount, "DT_JMPREL"); err != nil {
				return err
			}
			r.normalizeRelOffsets(r.JmpRel)
		case uint64(sizeofRela):
			jmprelCount, err := relocationEntryCount("DT_JMPREL", r.jmprelSize, uint64(sizeofRela))
			if err != nil {
				return err
			}
			r.logger.Info("jmprel read", "vaddr", r.jmprelVaddr, "count", jmprelCount, "type", "rela")
			if r.JmpRela, err = readArray[Elf64_Rela](r.File, fileOffset, jmprelCount, "DT_JMPRELA"); err != nil {
				return err
			}
			r.normalizeRelaOffsets(r.JmpRela)
		default:
			return fmt.Errorf("DT_JMPREL:bad_entry_size entry_size=%d", r.jmprelEntrySize)
		}
	}

	return nil
}

// maxSymbolChainWalk caps the GNU-hash chain walk so a corrupt/looping chain
// can't spin indefinitely. It is a sanity bound, not a spec limit.
const maxSymbolChainWalk = 1_000_000

// calculateSymbolCount determines the total number of symbols using hash tables
func (r *ElfReader) calculateSymbolCount() (uint64, error) {
	// Try standard .hash table first
	if r.hashVaddr != 0 {
		fileOffset := r.vaddrToOffset(r.hashVaddr)
		if _, err := r.File.Seek(int64(fileOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("hash:seek: %w", err)
		}

		var header HashHeader
		if err := binary.Read(r.File, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("hash:read: %w", err)
		}

		return uint64(header.Nchain), nil
	}

	// Fall back to .gnu.hash table
	if r.gnuHashVaddr != 0 {
		fileOffset := r.vaddrToOffset(r.gnuHashVaddr)
		r.logger.Debug("gnuhash read", "vaddr", r.gnuHashVaddr, "offset", fileOffset)

		if _, err := r.File.Seek(int64(fileOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("gnu_hash:seek: %w", err)
		}

		var header GNUHashHeader
		if err := binary.Read(r.File, binary.LittleEndian, &header); err != nil {
			return 0, fmt.Errorf("gnu_hash:read: %w", err)
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
			return 0, fmt.Errorf("gnu_hash:buckets_seek: %w", err)
		}
		if err := binary.Read(r.File, binary.LittleEndian, buckets); err != nil {
			return 0, fmt.Errorf("gnu_hash:buckets_read: %w", err)
		}

		// Scan ALL non-zero bucket chains to find the true maximum symbol index.
		// A bucket with a lower starting index can have a longer chain that extends
		// past the highest bucket's starting index.
		//
		// GNU hash semantics: chain entry k corresponds to symbol (symndx + k).
		// Bit 0 of a chain value marks the LAST symbol of that bucket's chain, and
		// that symbol is still a valid, counted symbol. The total symbol count is
		// therefore (max terminal symbol index) + 1 — the terminal index is
		// captured by the top-of-loop maxSymIdx update, so we must NOT increment
		// currentSymIndex when the chain terminator is seen.
		maxSymIdx := uint64(header.Symndx)
		seenBuckets := make(map[uint32]bool)
		seenChain := false

		// Hoist the file size out of the chain walk: it is invariant across the
		// up-to-maxSymbolChainWalk iterations, so stat'ing it per-iteration would
		// re-syscall needlessly.
		var fileSize uint64
		if info, err := r.File.Stat(); err == nil {
			fileSize = uint64(info.Size())
		}

		for _, startSymIdx := range buckets {
			if startSymIdx == 0 || seenBuckets[startSymIdx] {
				continue
			}
			if startSymIdx < header.Symndx {
				return 0, fmt.Errorf("gnu_hash:bad_bucket bucket=%d symndx=%d", startSymIdx, header.Symndx)
			}
			seenBuckets[startSymIdx] = true
			seenChain = true

			currentSymIndex := uint64(startSymIdx)
			for currentSymIndex < maxSymbolChainWalk {
				// Record this symbol index before reading its chain entry. If this
				// entry turns out to be the chain terminator, this index is the
				// last (and still valid) symbol of the chain.
				if currentSymIndex > maxSymIdx {
					maxSymIdx = currentSymIndex
				}
				chainIndex := currentSymIndex - uint64(header.Symndx)
				chainFileOffset := r.vaddrToOffset(chainsAddr + chainIndex*4)

				// Bound check: don't read past file
				if fileSize != 0 && chainFileOffset+4 > fileSize {
					break
				}

				if _, err := r.File.Seek(int64(chainFileOffset), io.SeekStart); err != nil {
					break
				}
				var chainVal uint32
				if err := binary.Read(r.File, binary.LittleEndian, &chainVal); err != nil {
					break
				}

				// Bit 0 = 1 marks end of chain. The current symbol index (already
				// recorded above) is the terminal symbol and is counted; do not
				// advance past it, or the result over-counts by one.
				if (chainVal & 1) != 0 {
					break
				}
				currentSymIndex++
			}
		}

		if !seenChain {
			return uint64(header.Symndx), nil
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
			r.logger.Info("runpath read", "tag", entry.Tag.String(), "path", r.runpath)
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
	maxGotEnd := uint64(0)
	found := false

	consider := func(ttype uint32, offset uint64) {
		var width uint64
		switch RelocationType(ttype) {
		case R_AARCH64_GLOB_DAT:
			width = sizeofPtr
		case R_AARCH64_TLSDESC:
			width = 2 * sizeofPtr // two-word TLS descriptor
		default:
			return
		}
		if offset < minGot {
			minGot = offset
		}
		end := offset + width
		if end > maxGotEnd {
			maxGotEnd = end
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
		r.gotSize = maxGotEnd - minGot
		r.logger.Debug("got calc", "start", r.gotVaddr, "size", r.gotSize)
	}

	// Calculate .got.plt size if we have PLT relocs
	if r.pltGotVaddr != 0 && r.jmprelSize > 0 && r.jmprelEntrySize > 0 {
		// Size = one slot per PLT entry + 3 linker-reserved leading slots.
		const pltGotReservedSlots = 3
		count := r.jmprelSize / r.jmprelEntrySize
		r.pltGotSize = (count + pltGotReservedSlots) * sizeofPtr
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

const (
	packedRelocMaxDecoded = 10_000_000

	packedGroupedByInfo        int64 = 1 // RELOCATION_GROUPED_BY_INFO_FLAG
	packedGroupedByOffsetDelta int64 = 2 // RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG
	packedGroupedByAddend      int64 = 4 // RELOCATION_GROUPED_BY_ADDEND_FLAG
	packedGroupHasAddend       int64 = 8 // RELOCATION_GROUP_HAS_ADDEND_FLAG
	packedGroupFlagMask              = packedGroupedByInfo | packedGroupedByOffsetDelta | packedGroupedByAddend | packedGroupHasAddend
)

func validatePackedGroupFlags(name string, flags int64) error {
	if flags < 0 || flags&^packedGroupFlagMask != 0 {
		return fmt.Errorf("%s:bad_group_flags flags=0x%x", name, flags)
	}
	return nil
}

func checkedInt64Add(name string, a int64, b int64) (int64, error) {
	const maxInt64 = int64(^uint64(0) >> 1)
	const minInt64 = -maxInt64 - 1
	if (b > 0 && a > maxInt64-b) || (b < 0 && a < minInt64-b) {
		return 0, fmt.Errorf("%s:overflow lhs=%d rhs=%d", name, a, b)
	}
	return a + b, nil
}

// slebCursor reads a sequence of SLEB128 values from a packed relocation blob,
// tracking position and producing consistent bad_sleb errors.
type slebCursor struct {
	buf  []byte
	pos  int
	name string
}

func (c *slebCursor) read(field string) (int64, error) {
	v, n, ok := decodeSLEB128Checked(c.buf[c.pos:])
	if !ok {
		return 0, fmt.Errorf("%s:%s:bad_sleb pos=%d remaining=%d", c.name, field, c.pos, len(c.buf)-c.pos)
	}
	c.pos += n
	return v, nil
}

// decodePackedRela decodes APS2/APA1 packed relocations (DT_ANDROID_RELA) into Elf64_Rela entries.
// APS2 matches bionic's packed_reloc_iterator: offsets and RELA addends are cumulative state.
func (r *ElfReader) decodePackedRela(fileOffset uint64, size uint64) ([]Elf64_Rela, error) {
	buf, err := r.readBoundedBlob(fileOffset, size, "android_rela")
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, fmt.Errorf("android_rela:too_short size=%d", len(buf))
	}
	magic := string(buf[:4])
	if magic != "APS2" && magic != "APA1" {
		return nil, fmt.Errorf("android_rela:bad_magic got=%q", magic)
	}

	if magic == "APA1" {
		return r.decodeAPA1Rela(buf)
	}

	var result []Elf64_Rela
	err = r.decodeAPS2Groups(buf, "android_rela", true, func(offset, info uint64, addend int64) error {
		result = append(result, Elf64_Rela{Offset: offset, Info: info, Addend: addend})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// decodeAPA1Rela decodes the APA1 (offset-delta / addend-delta pair) RELA stream.
func (r *ElfReader) decodeAPA1Rela(buf []byte) ([]Elf64_Rela, error) {
	c := &slebCursor{buf: buf, pos: 4, name: "android_rela"}
	pairs, err := c.read("pairs")
	if err != nil {
		return nil, err
	}
	if pairs < 0 || pairs > packedRelocMaxDecoded {
		return nil, fmt.Errorf("android_rela:bad_pairs pairs=%d", pairs)
	}
	var result []Elf64_Rela
	var offset, addend int64
	for i := int64(0); i < pairs; i++ {
		odelta, err := c.read("offset_delta")
		if err != nil {
			return nil, err
		}
		adelta, err := c.read("addend_delta")
		if err != nil {
			return nil, err
		}
		if offset, err = checkedInt64Add("android_rela:offset", offset, odelta); err != nil {
			return nil, err
		}
		if addend, err = checkedInt64Add("android_rela:addend", addend, adelta); err != nil {
			return nil, err
		}
		normOffset, err := r.normalizePackedRelocOffset(offset, "android_rela")
		if err != nil {
			return nil, err
		}
		result = append(result, Elf64_Rela{Offset: normOffset, Info: uint64(R_AARCH64_RELATIVE), Addend: addend})
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

	if magic == "APR1" {
		return r.decodeAPR1Rel(buf)
	}

	var result []Elf64_Rel
	err = r.decodeAPS2Groups(buf, "android_rel", false, func(offset, info uint64, _ int64) error {
		result = append(result, Elf64_Rel{Offset: offset, Info: info})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// decodeAPR1Rel decodes the APR1 (run-length count / delta pair) REL stream.
func (r *ElfReader) decodeAPR1Rel(buf []byte) ([]Elf64_Rel, error) {
	c := &slebCursor{buf: buf, pos: 4, name: "android_rel"}
	pairs, err := c.read("pairs")
	if err != nil {
		return nil, err
	}
	if pairs < 0 || pairs > packedRelocMaxDecoded {
		return nil, fmt.Errorf("android_rel:bad_pairs pairs=%d", pairs)
	}
	addr, err := c.read("initial_offset")
	if err != nil {
		return nil, err
	}

	var result []Elf64_Rel
	appendRel := func(offset int64) error {
		normOffset, err := r.normalizePackedRelocOffset(offset, "android_rel")
		if err != nil {
			return err
		}
		result = append(result, Elf64_Rel{Offset: normOffset, Info: uint64(R_AARCH64_RELATIVE)})
		return nil
	}
	if err := appendRel(addr); err != nil {
		return nil, err
	}
	for i := int64(0); i < pairs; i++ {
		count, err := c.read("pair_count")
		if err != nil {
			return nil, err
		}
		delta, err := c.read("pair_delta")
		if err != nil {
			return nil, err
		}
		if count < 0 || count > packedRelocMaxDecoded || int64(len(result))+count > packedRelocMaxDecoded {
			return nil, fmt.Errorf("android_rel:bad_pair_count count=%d", count)
		}
		for j := int64(0); j < count; j++ {
			if addr, err = checkedInt64Add("android_rel:offset", addr, delta); err != nil {
				return nil, err
			}
			if err := appendRel(addr); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

// decodeAPS2Groups decodes the APS2 grouped relocation stream shared by the REL
// and RELA packed decoders. When allowAddend is false any addend group flag is
// rejected (REL relocations carry no addend). Each decoded entry is passed to
// emit with its offset already normalized to a module-relative vaddr.
func (r *ElfReader) decodeAPS2Groups(buf []byte, name string, allowAddend bool, emit func(offset, info uint64, addend int64) error) error {
	c := &slebCursor{buf: buf, pos: 4, name: name}

	relocCount, err := c.read("reloc_count")
	if err != nil {
		return err
	}
	if relocCount < 0 || relocCount > packedRelocMaxDecoded {
		return fmt.Errorf("%s:bad_count count=%d", name, relocCount)
	}
	offset, err := c.read("initial_offset")
	if err != nil {
		return err
	}
	var addend int64
	var emitted int64

	for emitted < relocCount {
		groupSize, err := c.read("group_size")
		if err != nil {
			return err
		}
		groupFlags, err := c.read("group_flags")
		if err != nil {
			return err
		}
		if err := validatePackedGroupFlags(name, groupFlags); err != nil {
			return err
		}
		if groupSize <= 0 {
			return fmt.Errorf("%s:bad_group_size size=%d", name, groupSize)
		}
		if groupSize > relocCount-emitted {
			return fmt.Errorf("%s:group_overflow size=%d remaining=%d", name, groupSize, relocCount-emitted)
		}
		if !allowAddend && (groupFlags&(packedGroupedByAddend|packedGroupHasAddend)) != 0 {
			return fmt.Errorf("%s:unexpected_addend flags=0x%x", name, groupFlags)
		}

		var groupOffsetDelta int64
		if (groupFlags & packedGroupedByOffsetDelta) != 0 {
			if groupOffsetDelta, err = c.read("group_offset_delta"); err != nil {
				return err
			}
		}

		var groupInfo int64
		if (groupFlags & packedGroupedByInfo) != 0 {
			if groupInfo, err = c.read("group_info"); err != nil {
				return err
			}
			if groupInfo < 0 {
				return fmt.Errorf("%s:bad_group_info info=%d", name, groupInfo)
			}
		}

		entriesHaveAddends := allowAddend && (groupFlags&packedGroupHasAddend) != 0
		entriesShareAddend := allowAddend && (groupFlags&packedGroupedByAddend) != 0
		if entriesShareAddend && !entriesHaveAddends {
			return fmt.Errorf("%s:grouped_addend_without_addend flags=0x%x", name, groupFlags)
		}
		if entriesHaveAddends && entriesShareAddend {
			groupAddendDelta, err := c.read("group_addend_delta")
			if err != nil {
				return err
			}
			if addend, err = checkedInt64Add(name+":addend", addend, groupAddendDelta); err != nil {
				return err
			}
		} else if !entriesHaveAddends {
			addend = 0
		}

		for i := int64(0); i < groupSize; i++ {
			if (groupFlags & packedGroupedByOffsetDelta) != 0 {
				if offset, err = checkedInt64Add(name+":offset", offset, groupOffsetDelta); err != nil {
					return err
				}
			} else {
				entryOffsetDelta, err := c.read("entry_offset_delta")
				if err != nil {
					return err
				}
				if offset, err = checkedInt64Add(name+":offset", offset, entryOffsetDelta); err != nil {
					return err
				}
			}

			entryInfo := groupInfo
			if (groupFlags & packedGroupedByInfo) == 0 {
				if entryInfo, err = c.read("entry_info"); err != nil {
					return err
				}
				if entryInfo < 0 {
					return fmt.Errorf("%s:bad_entry_info info=%d", name, entryInfo)
				}
			}

			if entriesHaveAddends && !entriesShareAddend {
				addendDelta, err := c.read("entry_addend_delta")
				if err != nil {
					return err
				}
				if addend, err = checkedInt64Add(name+":addend", addend, addendDelta); err != nil {
					return err
				}
			}

			normOffset, err := r.normalizePackedRelocOffset(offset, name)
			if err != nil {
				return err
			}
			if err := emit(normOffset, uint64(entryInfo), addend); err != nil {
				return err
			}
			emitted++
		}
	}

	return nil
}

func (r *ElfReader) normalizePackedRelocOffset(offset int64, name string) (uint64, error) {
	if offset < 0 {
		return 0, fmt.Errorf("%s:negative_offset offset=%d", name, offset)
	}
	u := uint64(offset)
	if normalized, ok := r.normalizeLoadedAddress(u); ok {
		u = normalized
		switch name {
		case "android_rel":
			r.androidRelDirty = true
		case "android_rela":
			r.androidRelaDirty = true
		}
	}
	return u, nil
}

// DecodeSLEB128 decodes a signed LEB128 value from buf, returning the value and bytes consumed.
// Bails after 10 bytes (the max needed to encode an int64) to avoid spinning on corrupt input.
func DecodeSLEB128(buf []byte) (int64, int) {
	v, n, _ := decodeSLEB128Checked(buf)
	return v, n
}

func decodeSLEB128Checked(buf []byte) (int64, int, bool) {
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
			return result, i + 1, true
		}
	}
	return result, limit, false
}

// readBoundedBlob reads exactly `size` bytes at `fileOffset`.
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
			return nil, fmt.Errorf("%s:truncated_blob requested=%d remaining=%d", name, size, remaining)
		}
	}
	buf := make([]byte, size)
	if _, err := r.File.ReadAt(buf, int64(fileOffset)); err != nil {
		return nil, fmt.Errorf("%s:read_raw: %w", name, err)
	}
	return buf, nil
}
