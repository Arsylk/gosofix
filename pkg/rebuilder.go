package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
)

type ElfRebuilder struct {
	*ElfReader
	OutFile   *os.File
	TotalSize uint64

	sections          []Elf64_Shdr
	shstrtab          []byte
	sectionNameMap    map[string]uint32
	sectionNameLookup map[uint32]string
}

func NewElfRebuilder(reader *ElfReader, outputPath string) (*ElfRebuilder, error) {
	rebuilder := ElfRebuilder{
		ElfReader: reader,

		sections:          make([]Elf64_Shdr, 0),
		shstrtab:          []byte{0},
		sectionNameMap:    make(map[string]uint32),
		sectionNameLookup: make(map[uint32]string),
	}

	var err error
	rebuilder.OutFile, err = os.OpenFile(outputPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}

	return &rebuilder, nil
}

// WriteFixedElf copies the source file and writes fixed relocation values
func (r *ElfRebuilder) WriteFixedElf() error {
	// Calculate total file size from loaded segments (max Vaddr - min Vaddr)
	var minVaddr uint64 = ^uint64(0)
	var maxVaddr uint64 = 0
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD {
			if phdr.Vaddr < minVaddr {
				minVaddr = phdr.Vaddr
			}
			if phdr.Vaddr+phdr.Memsz > maxVaddr {
				maxVaddr = phdr.Vaddr + phdr.Memsz
			}
		}
	}
	if minVaddr != ^uint64(0) {
		r.TotalSize = maxVaddr - minVaddr
	}

	if err := r.rebuildFileLayout(); err != nil {
		return fmt.Errorf("failed to rebuild file layout: %w", err)
	}

	// Fix ELF Header - write normalized Entry address.
	if err := r.writeAtOffset(ehOffEntry, r.ElfHeader.Entry); err != nil {
		return fmt.Errorf("failed to write ehdr entry: %w", err)
	}

	// Fix program headers - write the whole entry back. rebuildFileLayout has
	// already updated Offset and (for PT_LOAD) Filesz; p_paddr is set equal to
	// p_vaddr. Type/Flags/Align are unchanged from the input header, so rewriting
	// them is a no-op that keeps the write symmetric with the struct read.
	phdrOffset := r.ElfHeader.PhdrOffset
	for i := range r.Phdrs {
		phdr := r.Phdrs[i]
		phdr.Paddr = phdr.Vaddr
		offset := phdrOffset + uint64(i)*uint64(r.ElfHeader.Phentsize)
		if err := r.writeAtOffset(offset, phdr); err != nil {
			return fmt.Errorf("failed to write phdr %d: %w", i, err)
		}
		r.logger.Debug("phdr write", "index", i, "type", phdr.Type.String(), "vaddr", phdr.Vaddr, "paddr", phdr.Paddr, "offset", phdr.Offset, "file_size", phdr.Filesz, "memory_size", phdr.Memsz)
	}
	r.logger.Info("phdrs write", "count", len(r.Phdrs))

	if err := r.writeFixedInitsFinis(); err != nil {
		return fmt.Errorf("failed to write init/fini arrays: %w", err)
	}

	// Apply relocation patches to target addresses (data/GOT)
	if err := r.writeFixedRelocs(); err != nil {
		return fmt.Errorf("failed to write relocs: %w", err)
	}

	if err := r.writeRelocationTables(); err != nil {
		return fmt.Errorf("failed to patch relocation tables: %w", err)
	}

	// Patch dynamic section in place
	if err := r.writeDynamicSection(); err != nil {
		return fmt.Errorf("failed to patch dynamic section: %w", err)
	}

	// Build and write section headers first (populates r.sections)
	if err := r.writeSectionHeaders(); err != nil {
		return fmt.Errorf("failed to write section headers: %w", err)
	}

	// Now that sections exist, fix symbol section indices
	r.fixSymbolSectionIndices()
	if err := r.writeSymbolTable(); err != nil {
		return fmt.Errorf("failed to patch symbols: %w", err)
	}

	// Patch leftover absolute in-module pointers not covered by relocation metadata
	if err := r.patchResidualBasePointers(); err != nil {
		return fmt.Errorf("failed to patch residual pointers: %w", err)
	}

	return nil
}

func (r *ElfRebuilder) addSection(name string, shType SHT_Type, flags uint64, addr uint64, size uint64, link uint32, info uint32, entsize uint64) int {
	nameOffset := r.addSectionName(name)
	fileOffset := r.vaddrToOffset(addr)

	// Calculate correct alignment: must be power of 2 and divide addr
	var align uint64 = 8
	// SHT_NOTE usually implies 4-byte alignment on Linux/Android even for 64-bit binaries
	// If we force 8-byte alignment on a 4-byte aligned note section, tools like readelf
	// will miscalculate note boundaries.
	if shType == SHT_NOTE {
		align = 4
	}

	if addr != 0 {
		for align > 1 && addr%align != 0 {
			align >>= 1
		}
	}

	section := Elf64_Shdr{
		Name:      nameOffset,
		Type:      shType,
		Flags:     flags,
		Addr:      addr,
		Offset:    fileOffset,
		Size:      size,
		Link:      link,
		Info:      info,
		Addralign: align,
		Entsize:   entsize,
	}
	idx := len(r.sections)
	r.sections = append(r.sections, section)
	return idx
}

func (r *ElfRebuilder) addSectionName(name string) uint32 {
	if name == "" {
		return 0
	}
	if offset, ok := r.sectionNameMap[name]; ok {
		return offset
	}
	offset := uint32(len(r.shstrtab))
	r.shstrtab = append(r.shstrtab, []byte(name)...)
	r.shstrtab = append(r.shstrtab, 0)
	r.sectionNameMap[name] = offset
	r.sectionNameLookup[offset] = name
	return offset
}

func (r *ElfRebuilder) readSectionName(nameOffset uint32) string {
	return r.sectionNameLookup[nameOffset]
}

// sectionInfo is a pending section-header description gathered during rebuild,
// before it is turned into an Elf64_Shdr.
type sectionInfo struct {
	name    string
	shType  SHT_Type
	flags   uint64
	addr    uint64
	size    uint64
	link    uint32
	info    uint32
	entsize uint64
}

// interval is a half-open [start, end) address range used for gap analysis.
type interval struct {
	start, end uint64
}

// pltRelocSection returns the section name and type for DT_JMPREL, keyed on its
// entry size (REL vs RELA). Returns ("", SHT_NULL) when there is no PLT reloc.
func (r *ElfRebuilder) pltRelocSection() (string, SHT_Type) {
	if r.jmprelVaddr == 0 {
		return "", SHT_NULL
	}
	if r.jmprelEntrySize == uint64(sizeofRel) {
		return ".rel.plt", SHT_REL
	}
	return ".rela.plt", SHT_RELA
}

// synthesizeLoadGapSections emits PROGBITS coverage sections (.text/.rw/.ro) for
// the parts of each PT_LOAD segment not already claimed by a known metadata
// section, so analysis tools see the whole image. Executable segments emit only
// their single largest gap as .text to avoid overlay conflicts.
func (r *ElfRebuilder) synthesizeLoadGapSections(knownSections []sectionInfo) []sectionInfo {
	loadSectionName := func(phdr Elf64_Phdr) string {
		if (phdr.Flags & PF_X) != 0 {
			return ".text"
		}
		if (phdr.Flags & PF_W) != 0 {
			return ".rw"
		}
		return ".ro"
	}

	loadSectionFlags := func(phdr Elf64_Phdr) uint64 {
		flags := uint64(SHF_ALLOC)
		if (phdr.Flags & PF_X) != 0 {
			flags |= SHF_EXECINSTR
		}
		if (phdr.Flags & PF_W) != 0 {
			flags |= SHF_WRITE
		}
		return flags
	}

	// nameOccurrence counts how many PT_LOAD segments of each base name (.text/.rw/.ro)
	// we've seen. Used to disambiguate sections from multiple writable/read-only segments.
	nameOccurrence := map[string]int{}

	var out []sectionInfo
	for _, phdr := range r.Phdrs {
		if phdr.Type != PT_LOAD || phdr.Memsz == 0 {
			continue
		}

		var occupied []interval
		// Add ELF header and Phdrs if they are in this segment
		if phdr.Offset == 0 {
			start := phdr.Vaddr
			end := phdr.Vaddr + r.ElfHeader.PhdrOffset + uint64(r.ElfHeader.Phnum*r.ElfHeader.Phentsize)
			occupied = append(occupied, interval{start, end})
		}

		// Add knownSections that overlap this segment (clip to segment bounds).
		segStart := phdr.Vaddr
		segEnd := phdr.Vaddr + phdr.Memsz
		for _, ks := range knownSections {
			ksEnd := ks.addr + ks.size
			if ksEnd <= segStart || ks.addr >= segEnd {
				continue // no overlap
			}
			// Clip the known section to the segment bounds.
			occupied = append(occupied, interval{max(ks.addr, segStart), min(ksEnd, segEnd)})
		}

		// Sort occupied manually
		sort.Slice(occupied, func(i, j int) bool {
			return occupied[i].start < occupied[j].start
		})

		var merged []interval
		for _, occ := range occupied {
			if len(merged) == 0 {
				merged = append(merged, occ)
			} else {
				last := &merged[len(merged)-1]
				if occ.start <= last.end {
					if occ.end > last.end {
						last.end = occ.end
					}
				} else {
					merged = append(merged, occ)
				}
			}
		}

		curr := phdr.Vaddr
		var gaps []interval
		for _, m := range merged {
			if m.start > curr {
				gaps = append(gaps, interval{curr, m.start})
			}
			if m.end > curr {
				curr = m.end
			}
		}
		if curr < phdr.Vaddr+phdr.Memsz {
			gaps = append(gaps, interval{curr, phdr.Vaddr + phdr.Memsz})
		}

		largestGapIdx := -1
		var largestGapSize uint64
		for i, gap := range gaps {
			size := gap.end - gap.start
			if size > largestGapSize {
				largestGapSize = size
				largestGapIdx = i
			}
		}

		base := loadSectionName(phdr)
		segIdx := nameOccurrence[base]
		nameOccurrence[base]++
		segSuffix := ""
		if segIdx > 0 {
			// First segment of this kind gets no suffix; subsequent get "1", "2", …
			segSuffix = fmt.Sprintf("%d", segIdx)
		}

		for i, gap := range gaps {
			size := gap.end - gap.start
			if size == 0 {
				continue
			}
			// For executable segments, only emit the largest gap as a single .text section.
			// Smaller gaps (between metadata sections) are skipped to prevent Ghidra from
			// creating .text as an overlay when gap addresses conflict with metadata sections.
			if (phdr.Flags&PF_X) != 0 && i != largestGapIdx {
				continue
			}
			name := base + segSuffix
			if i != largestGapIdx {
				name = fmt.Sprintf("%s.%d", name, i)
			}
			out = append(out, sectionInfo{
				name:    name,
				shType:  SHT_PROGBITS,
				flags:   loadSectionFlags(phdr),
				addr:    gap.start,
				size:    size,
				entsize: 0,
			})
		}
	}
	return out
}

func (r *ElfRebuilder) writeSectionHeaders() error {
	// Mandatory null section at index 0.
	_ = r.addSection("", SHT_NULL, 0, 0, 0, 0, 0, 0)

	// Track indices for link fields
	var dynstrIdx, dynsymIdx, pltGotIdx int
	pltRelocName, _ := r.pltRelocSection()

	var knownSections []sectionInfo

	// 1. Collect all known metadata sections from dynamic tags
	if r.strtabVaddr != 0 && r.strtabSize != 0 {
		knownSections = append(knownSections, sectionInfo{".dynstr", SHT_STRTAB, SHF_ALLOC,
			r.strtabVaddr, r.strtabSize, 0, 0, 0})
	}
	if r.symtabVaddr != 0 && r.symCount > 0 {
		symSize := r.symCount * sizeofSym
		// sh_info for SHT_DYNSYM is the index of the first non-local symbol.
		// If every symbol is local, it must equal the symbol count.
		firstGlobalIdx := uint32(len(r.Symbols))
		for i, sym := range r.Symbols {
			if sym.StBind() != STB_LOCAL {
				firstGlobalIdx = uint32(i)
				break
			}
		}
		knownSections = append(knownSections, sectionInfo{".dynsym", SHT_DYNSYM, SHF_ALLOC,
			r.symtabVaddr, symSize, 0, firstGlobalIdx, sizeofSym})
	}
	if r.hashVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".hash", SHT_HASH, SHF_ALLOC,
			r.hashVaddr, r.hashSize, 0, 0, 4})
	}
	if r.gnuHashVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".gnu.hash", SHT_GNU_HASH, SHF_ALLOC,
			r.gnuHashVaddr, r.gnuHashSize, 0, 0, 0})
	}
	if r.versymVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".gnu.version", SHT_GNU_VERSYM, SHF_ALLOC,
			r.versymVaddr, r.symCount * 2, 0, 0, 2})
	}
	if r.verneedVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".gnu.version_r", SHT_GNU_VERNEED, SHF_ALLOC,
			r.verneedVaddr, r.verneedSize, 0, uint32(r.verneedNum), 0})
	}
	if r.relaVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".rela.dyn", SHT_RELA, SHF_ALLOC,
			r.relaVaddr, r.relaSize, 0, 0, sizeofRela})
	}
	if r.relVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".rel.dyn", SHT_REL, SHF_ALLOC,
			r.relVaddr, r.relSize, 0, 0, sizeofRel})
	}
	if r.relrVaddr != 0 && r.relrSize != 0 {
		relrType := r.relrSectionType
		if relrType == SHT_NULL {
			relrType = SHT_RELR
		}
		knownSections = append(knownSections, sectionInfo{".relr.dyn", relrType, SHF_ALLOC,
			r.relrVaddr, r.relrSize, 0, 0, sizeofPtr})
	}
	if r.androidRelVaddr != 0 && r.androidRelSize != 0 {
		knownSections = append(knownSections, sectionInfo{".android.rel.dyn", SHT_ANDROID_REL, SHF_ALLOC,
			r.androidRelVaddr, r.androidRelSize, 0, 0, 0})
	}
	if r.androidRelaVaddr != 0 && r.androidRelaSize != 0 {
		knownSections = append(knownSections, sectionInfo{".android.rela.dyn", SHT_ANDROID_RELA, SHF_ALLOC,
			r.androidRelaVaddr, r.androidRelaSize, 0, 0, 0})
	}
	if r.jmprelVaddr != 0 {
		name, shType := r.pltRelocSection()
		knownSections = append(knownSections, sectionInfo{name, shType, SHF_ALLOC | SHF_INFO_LINK,
			r.jmprelVaddr, r.jmprelSize, 0, 0, r.jmprelEntrySize})
	}
	if r.dynamicVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
			r.dynamicVaddr, r.dynamicSize, 0, 0, sizeofDyn})
	}
	if r.gotVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
			r.gotVaddr, r.gotSize, 0, 0, sizeofPtr})
	}
	if r.pltGotVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
			r.pltGotVaddr, r.pltGotSize, 0, 0, sizeofPtr})
	}
	if r.initArrayVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".init_array", SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.initArrayVaddr, r.initArraySize, 0, 0, sizeofPtr})
	}
	if r.finiArrayVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".fini_array", SHT_FINI_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.finiArrayVaddr, r.finiArraySize, 0, 0, sizeofPtr})
	}
	if r.preinitArrayVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".preinit_array", SHT_PREINIT_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.preinitArrayVaddr, r.preinitArraySize, 0, 0, sizeofPtr})
	}

	// Add additional metadata found in program headers
	if r.ehFrameHdrVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".eh_frame_hdr", SHT_PROGBITS, SHF_ALLOC,
			r.ehFrameHdrVaddr, r.ehFrameHdrSize, 0, 0, 4})
	}
	if r.noteVaddr != 0 {
		// Generic name — a single PT_NOTE may concatenate build-id, ABI tag, etc.
		// We don't parse the contents, so don't claim a specific identity.
		knownSections = append(knownSections, sectionInfo{".note", SHT_NOTE, SHF_ALLOC,
			r.noteVaddr, r.noteSize, 0, 0, 4})
	}

	// 2. Add deterministic PT_LOAD-backed coverage sections. These represent
	// authoritative memory coverage, not guessed original topology.
	finalSections := append([]sectionInfo{}, knownSections...)
	finalSections = append(finalSections, r.synthesizeLoadGapSections(knownSections)...)

	// 3. Add all sections to the rebuilder, sorted by address.
	// For identical addresses, add metadata sections before broad PT_LOAD coverage.
	sort.Slice(finalSections, func(i, j int) bool {
		if finalSections[i].addr != finalSections[j].addr {
			return finalSections[i].addr < finalSections[j].addr
		}
		if finalSections[i].size != finalSections[j].size {
			return finalSections[i].size < finalSections[j].size
		}
		return finalSections[i].name < finalSections[j].name
	})

	seen := make(map[string]struct{})
	for _, s := range finalSections {
		if s.size == 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d:%d:%d", s.name, s.addr, s.size, s.shType)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		idx := r.addSection(s.name, s.shType, s.flags, s.addr, s.size, s.link, s.info, s.entsize)
		switch s.name {
		case ".dynstr":
			dynstrIdx = idx
		case ".dynsym":
			dynsymIdx = idx
		case ".got.plt":
			pltGotIdx = idx
		}
	}

	// 4. Update link fields. The PLT-reloc sh_info points at the section the
	// relocations apply to (.got.plt) per the ELF spec; tools rely on it to
	// recover the PLT/GOT pairing.
	for i := 1; i < len(r.sections); i++ {
		sec := &r.sections[i]
		secName := r.readSectionName(sec.Name)
		switch sec.Type {
		case SHT_DYNSYM:
			sec.Link = uint32(dynstrIdx)
		case SHT_HASH, SHT_GNU_HASH, SHT_GNU_VERSYM, SHT_REL, SHT_RELA, SHT_ANDROID_REL, SHT_ANDROID_RELA:
			sec.Link = uint32(dynsymIdx)
			if pltRelocName != "" && secName == pltRelocName && pltGotIdx != 0 {
				sec.Info = uint32(pltGotIdx)
			}
		case SHT_DYNAMIC, SHT_GNU_VERNEED:
			sec.Link = uint32(dynstrIdx)
		}
	}

	// 5. Add .shstrtab at the end
	r.addSectionName(".shstrtab")
	shstrtabIdx := r.addSection(".shstrtab", SHT_STRTAB, 0, 0, uint64(len(r.shstrtab)), 0, 0, 0)

	// Calculate where to write (end of file)
	fileInfo, err := r.OutFile.Stat()
	if err != nil {
		return err
	}
	shstrtabOffset := AlignUp(uint64(fileInfo.Size()), 8)
	shdrOffset := AlignUp(shstrtabOffset+uint64(len(r.shstrtab)), 8)

	// Update .shstrtab offset
	ss := &r.sections[shstrtabIdx]
	ss.Addr = 0
	ss.Offset = shstrtabOffset

	// Write .shstrtab data to file
	if _, err := r.OutFile.Seek(int64(shstrtabOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to shstrtab: %w", err)
	}
	if _, err := r.OutFile.Write(r.shstrtab); err != nil {
		return fmt.Errorf("failed to write shstrtab: %w", err)
	}

	// Write section headers
	for i, section := range r.sections {
		offset := shdrOffset + uint64(i)*uint64(sizeofShdr)
		if err := r.writeAtOffset(offset, &section); err != nil {
			return err
		}
		r.logger.Info("shdr write", "index", i, "addr", section.Addr, "size", section.Size, "name", r.readSectionName(section.Name))
	}

	if err := r.writeAtOffset(ehOffShoff, shdrOffset); err != nil {
		return err
	}
	eShEntSize := uint16(sizeofShdr)
	if err := r.writeAtOffset(ehOffShentsize, eShEntSize); err != nil {
		return err
	}
	eShNum := uint16(len(r.sections))
	if err := r.writeAtOffset(ehOffShnum, eShNum); err != nil {
		return err
	}
	eShStrNdx := uint16(shstrtabIdx)
	if err := r.writeAtOffset(ehOffShstrndx, eShStrNdx); err != nil {
		return err
	}
	r.logger.Info("ehdr write", "section_header_offset", shdrOffset, "section_count", eShNum, "shstr_index", eShStrNdx)

	return nil
}

// fixSymbolSectionIndices remaps symbols only into authoritative sections.
// It prefers explicit metadata sections first, then falls back to PT_LOAD-backed coverage sections.
func (r *ElfRebuilder) fixSymbolSectionIndices() {
	for i := range r.Symbols {
		sym := &r.Symbols[i]
		if sym.Value == 0 || sym.Shndx == 0 {
			continue
		}
		if sym.Shndx >= 0xff00 {
			continue
		}
		newShndx := r.findAuthoritativeSectionForAddr(sym.Value)
		if newShndx != 0 {
			sym.Shndx = newShndx
		}
	}
}

func (r *ElfRebuilder) findAuthoritativeSectionForAddr(addr uint64) uint16 {
	var bestIdx uint16
	var bestSize uint64 = ^uint64(0)
	for i, sec := range r.sections {
		if i == 0 || sec.Type == SHT_NULL || sec.Addr == 0 || sec.Size == 0 {
			continue
		}
		if addr < sec.Addr || addr >= sec.Addr+sec.Size {
			continue
		}
		// Prefer the smallest (most specific) matching section.
		// This ensures metadata sections like .dynstr are preferred over
		// broad coverage sections like .text when addresses overlap.
		if sec.Size < bestSize {
			bestSize = sec.Size
			bestIdx = uint16(i)
		}
	}
	return bestIdx
}

func pointerArrayCount(name string, size uint64) (uint64, error) {
	if size%sizeofPtr != 0 {
		return 0, fmt.Errorf("%s size %d is not pointer-aligned", name, size)
	}
	return size / sizeofPtr, nil
}

// normalizePointerArray rewrites each pointer slot in an init/fini/preinit array,
// subtracting the dump base from any word that still holds a runtime address.
func (r *ElfRebuilder) normalizePointerArray(name string, vaddr, size uint64) error {
	if size == 0 || vaddr == 0 {
		return nil
	}
	count, err := pointerArrayCount(name, size)
	if err != nil {
		return err
	}
	for i := range count {
		fileOffset := r.vaddrToOffset(vaddr + i*sizeofPtr)
		value := r.readUint64OutAt(fileOffset)
		newVal := r.normalizeLoadedAddressValue(value)
		if newVal != value {
			if err := r.writeAtOffset(fileOffset, newVal); err != nil {
				return fmt.Errorf("failed to write %s: %w", name, err)
			}
			r.logger.Debug(name+" write", "index", i, "offset", fileOffset, "value", newVal)
		}
	}
	r.logger.Info(name+" write", "count", count)
	return nil
}

// writeFixedInitsFinis writes addresses for init_array, fini_array & preinit_array.
func (r *ElfRebuilder) writeFixedInitsFinis() error {
	// DT_INIT and DT_FINI are already normalized as dynamic tag values
	// in ReadDyns. The values ARE the function addresses — we must not
	// read or modify bytes at those addresses (they contain code, not pointers).
	if err := r.normalizePointerArray("init_array", r.initArrayVaddr, r.initArraySize); err != nil {
		return err
	}
	if err := r.normalizePointerArray("fini_array", r.finiArrayVaddr, r.finiArraySize); err != nil {
		return err
	}
	if err := r.normalizePointerArray("preinit_array", r.preinitArrayVaddr, r.preinitArraySize); err != nil {
		return err
	}
	return nil
}

// applyRelRelocs patches every data-relocation target slot in a REL table.
func (r *ElfRebuilder) applyRelRelocs(name string, list []Elf64_Rel) error {
	for i, rel := range list {
		relocType := rel.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug(name+" skip", "index", i, "type", relocType.String(), "reason", "unsupported_or_none")
			continue
		}
		// rel.Offset is already normalized to relative Vaddr.
		targetFileOffset, err := r.relocationTargetOffset(rel.Offset)
		if err != nil {
			return fmt.Errorf("failed to map %s target at idx %d: %w", name, i, err)
		}
		fixedVal := r.computeRelValue(&rel, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
		r.logger.Debug(name+" write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", relocType.String())
	}
	return nil
}

// applyRelaRelocs patches every data-relocation target slot in a RELA table.
func (r *ElfRebuilder) applyRelaRelocs(name string, list []Elf64_Rela) error {
	for i, rela := range list {
		relocType := rela.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug(name+" skip", "index", i, "type", relocType.String(), "reason", "unsupported_or_none")
			continue
		}
		targetFileOffset, err := r.relocationTargetOffset(rela.Offset)
		if err != nil {
			return fmt.Errorf("failed to map %s target at idx %d: %w", name, i, err)
		}
		fixedVal := r.computeRelaValue(&rela, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
		r.logger.Debug(name+" write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", relocType.String())
	}
	return nil
}

// relTable / relaTable pair a table's log name with its entries. relTables and
// relaTables enumerate the canonical REL/RELA relocation tables in one place so
// every pass (target patching, TLSDESC second slots) iterates the same set.
type relTable struct {
	name string
	list []Elf64_Rel
}

type relaTable struct {
	name string
	list []Elf64_Rela
}

func (r *ElfRebuilder) relTables() []relTable {
	return []relTable{{"rel", r.Rel}, {"jmprel", r.JmpRel}, {"android_rel", r.AndroidRel}}
}

func (r *ElfRebuilder) relaTables() []relaTable {
	return []relaTable{{"rela", r.Rela}, {"jmprela", r.JmpRela}, {"android_rela", r.AndroidRela}}
}

// writeFixedRelocs writes REL, RELA, JMPREL(A), Android-packed and RELR targets.
func (r *ElfRebuilder) writeFixedRelocs() error {
	for _, t := range r.relTables() {
		if err := r.applyRelRelocs(t.name, t.list); err != nil {
			return err
		}
	}
	for _, t := range r.relaTables() {
		if err := r.applyRelaRelocs(t.name, t.list); err != nil {
			return err
		}
	}

	// Fix RELR relocations — all entries are R_AARCH64_RELATIVE
	if len(r.Relr) > 0 {
		var where uint64
		var relrCount int
		haveAnchor := false
		for _, entry := range r.Relr {
			if (entry & 1) == 0 {
				// Even entry: absolute offset to patch
				where = entry
				if rebased, ok := r.normalizeLoadedAddress(where); ok {
					where = rebased
				}
				if where == 0 {
					// A zero anchor would imply patching the ELF header — almost
					// certainly malformed RELR data. Skip and continue.
					r.logger.Warn("relr skip", "reason", "zero_anchor", "raw_entry", entry)
					where += sizeofPtr
					haveAnchor = false
					continue
				}
				if err := r.patchRelrAt(where); err != nil {
					return err
				}
				relrCount++
				where += sizeofPtr
				haveAnchor = true
			} else {
				if !haveAnchor {
					r.logger.Warn("relr skip", "reason", "bitmap_without_anchor", "raw_entry", entry)
					continue
				}
				// Odd entry: bitmap, each of bits 1..63 covers a pointer-width slot.
				const relrBitmapSlots = 63 // bits per RELR word minus the flag bit
				for i := uint(0); i < relrBitmapSlots; i++ {
					if (entry & (1 << (i + 1))) != 0 {
						if err := r.patchRelrAt(where + uint64(i)*sizeofPtr); err != nil {
							return err
						}
						relrCount++
					}
				}
				where += relrBitmapSlots * sizeofPtr
			}
		}
		r.logger.Info("relr write", "entries", len(r.Relr), "patched_count", relrCount)
	}

	if err := r.patchTLSDESCSecondSlots(); err != nil {
		return err
	}

	r.logger.Info("relocs write", "count", len(r.Rel)+len(r.Rela)+len(r.JmpRel)+len(r.JmpRela)+len(r.AndroidRel)+len(r.AndroidRela))

	return nil
}

// patchRelrAt patches a single RELR location by subtracting base from the stored value
func (r *ElfRebuilder) patchRelrAt(vaddr uint64) error {
	fileOffset, err := r.relocationTargetOffset(vaddr)
	if err != nil {
		return err
	}
	return r.patchNormalizedWord(fileOffset, "relr")
}

func (r *ElfRebuilder) patchNormalizedWord(fileOffset uint64, name string) error {
	currentVal := r.readUint64OutAt(fileOffset)
	newVal := r.normalizeLoadedAddressValue(currentVal)
	if newVal != currentVal {
		if err := r.writeAtOffset(fileOffset, newVal); err != nil {
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
	}
	return nil
}

func (r *ElfRebuilder) patchTLSDESCSecond(kind string, index int, vaddr uint64) error {
	secondSlot, err := r.relocationTargetOffset(vaddr + sizeofPtr)
	if err != nil {
		return fmt.Errorf("failed to map %s tlsdesc second slot at idx %d: %w", kind, index, err)
	}
	if err := r.patchNormalizedWord(secondSlot, "tlsdesc"); err != nil {
		return err
	}
	r.logger.Debug("tlsdesc second write", "kind", kind, "index", index, "offset", secondSlot)
	return nil
}

func (r *ElfRebuilder) patchTLSDESCSecondSlots() error {
	for _, t := range r.relTables() {
		for i, rel := range t.list {
			if rel.Type() == R_AARCH64_TLSDESC {
				if err := r.patchTLSDESCSecond(t.name, i, rel.Offset); err != nil {
					return err
				}
			}
		}
	}
	for _, t := range r.relaTables() {
		for i, rela := range t.list {
			if rela.Type() == R_AARCH64_TLSDESC {
				if err := r.patchTLSDESCSecond(t.name, i, rela.Offset); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// writeSymbolTable patches the existing symbol table in the file
func (r *ElfRebuilder) writeSymbolTable() error {
	if r.symtabVaddr == 0 || len(r.Symbols) == 0 {
		return nil
	}

	symtabFileOffset := r.vaddrToOffset(r.symtabVaddr)
	// Write the entire symbol table back to the file
	if err := r.writeAtOffset(symtabFileOffset, r.Symbols); err != nil {
		return fmt.Errorf("failed to write symbol table: %w", err)
	}

	r.logger.Info("syms write", "count", len(r.Symbols))
	return nil
}

// writeRelocationTables writes normalized relocation metadata back to the output.
// The relocation target slots are fixed separately by writeFixedRelocs.
func (r *ElfRebuilder) writeRelocationTables() error {
	if r.relVaddr != 0 && len(r.Rel) > 0 {
		if err := r.writeAtOffset(r.vaddrToOffset(r.relVaddr), r.Rel); err != nil {
			return fmt.Errorf("failed to write DT_REL table: %w", err)
		}
		r.logger.Info("rel table write", "count", len(r.Rel))
	}

	if r.relaVaddr != 0 && len(r.Rela) > 0 {
		if err := r.writeAtOffset(r.vaddrToOffset(r.relaVaddr), r.Rela); err != nil {
			return fmt.Errorf("failed to write DT_RELA table: %w", err)
		}
		r.logger.Info("rela table write", "count", len(r.Rela))
	}

	if r.jmprelVaddr != 0 {
		switch {
		case len(r.JmpRel) > 0 && len(r.JmpRela) > 0:
			return fmt.Errorf("DT_JMPREL has both REL and RELA decoded tables")
		case len(r.JmpRel) > 0:
			if err := r.writeAtOffset(r.vaddrToOffset(r.jmprelVaddr), r.JmpRel); err != nil {
				return fmt.Errorf("failed to write DT_JMPREL REL table: %w", err)
			}
			r.logger.Info("jmprel table write", "count", len(r.JmpRel), "type", "rel")
		case len(r.JmpRela) > 0:
			if err := r.writeAtOffset(r.vaddrToOffset(r.jmprelVaddr), r.JmpRela); err != nil {
				return fmt.Errorf("failed to write DT_JMPREL RELA table: %w", err)
			}
			r.logger.Info("jmprel table write", "count", len(r.JmpRela), "type", "rela")
		}
	}

	if r.relrVaddr != 0 && len(r.Relr) > 0 {
		normalized := append([]uint64(nil), r.Relr...)
		for i, entry := range normalized {
			if (entry & 1) == 0 {
				if rebased, ok := r.normalizeLoadedAddress(entry); ok {
					normalized[i] = rebased
				}
			}
		}
		if err := r.writeAtOffset(r.vaddrToOffset(r.relrVaddr), normalized); err != nil {
			return fmt.Errorf("failed to write DT_RELR table: %w", err)
		}
		r.Relr = normalized
		r.logger.Info("relr table write", "count", len(r.Relr))
	}

	return nil
}

// writeDynamicSection patches the existing dynamic section in the file
func (r *ElfRebuilder) writeDynamicSection() error {
	if r.dynamicVaddr == 0 || len(r.Dyns) == 0 {
		return nil
	}

	dynamicFileOffset := r.vaddrToOffset(r.dynamicVaddr)
	// Write the entire dynamic section back to the file
	if err := r.writeAtOffset(dynamicFileOffset, r.Dyns); err != nil {
		return fmt.Errorf("failed to write dynamic section: %w", err)
	}

	r.logger.Info("dyns write", "count", len(r.Dyns))
	return nil
}

// isDataRelocation returns true for 64-bit data relocation types that modify
// data slots. Most write one 8-byte word; TLSDESC is a two-word descriptor and
// gets its second word patched explicitly. Code relocations (ADR, CALL26, etc.)
// modify 4-byte instructions and must not be treated as data writes.
func isDataRelocation(rt RelocationType) bool {
	switch rt {
	case R_AARCH64_NONE:
		return false
	case R_AARCH64_ABS64, R_AARCH64_PREL64, R_AARCH64_RELATIVE,
		R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_COPY,
		R_AARCH64_TLS_DTPMOD, R_AARCH64_TLS_DTPREL, R_AARCH64_TLS_TPREL,
		R_AARCH64_TLSDESC, R_AARCH64_IRELATIVE:
		return true
	default:
		return false
	}
}

// sharedDataRelocValue handles the relocation types whose normalized slot value
// is identical for REL and RELA — everything except RELATIVE (which differs on
// the explicit vs in-place addend) and the symbol-based default. Returns
// (value, true) when the type is handled here.
func (r *ElfRebuilder) sharedDataRelocValue(relocType RelocationType, fileOffset uint64) (uint64, bool) {
	switch relocType {
	case R_AARCH64_COPY:
		// Preserve the in-memory copy.
		return r.readUint64OutAt(fileOffset), true
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64:
		// For external symbols the slot holds the runtime-resolved address; prefer
		// it (normalizing only in-module targets) so we don't zero it.
		return r.normalizeLoadedAddressValue(r.readUint64OutAt(fileOffset)), true
	case R_AARCH64_IRELATIVE:
		// The slot holds the resolver's return value, not the r_addend resolver
		// address; preserve it, normalizing only if it points back into this dump.
		return r.normalizeLoadedAddressValue(r.readUint64OutAt(fileOffset)), true
	case R_AARCH64_PREL64:
		// Slot stores S + A - P; base-invariant in a dump, so leave it as-is.
		return r.readUint64OutAt(fileOffset), true
	case R_AARCH64_TLS_DTPMOD, R_AARCH64_TLS_DTPREL, R_AARCH64_TLS_TPREL:
		// TLS slots are module/block-relative runtime state; preserve them.
		return r.readUint64OutAt(fileOffset), true
	case R_AARCH64_TLSDESC:
		// Two-word runtime descriptor: first word here, second in patchTLSDESCSecondSlots.
		return r.normalizeLoadedAddressValue(r.readUint64OutAt(fileOffset)), true
	default:
		return 0, false
	}
}

// computeRelValue computes the fixed value for a REL relocation.
// REL has no explicit addend — for relocation types that need one, the addend
// is read from the slot at fileOffset (the in-place value).
func (r *ElfRebuilder) computeRelValue(rel *Elf64_Rel, fileOffset uint64) uint64 {
	relocType := rel.Type()
	relocSym := rel.Sym()

	var S uint64
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.Name))
		r.logger.Debug("rel resolve", "symbol", symName, "type", sym.StType().String(), "bind", sym.StBind().String())
		S = sym.Value
	}

	// R_AARCH64_NONE is filtered by isDataRelocation before reaching here.
	if v, ok := r.sharedDataRelocValue(relocType, fileOffset); ok {
		return v
	}
	switch relocType {
	case R_AARCH64_RELATIVE:
		// In-place value is base + addend; normalize to leave just the addend.
		return r.normalizeLoadedAddressValue(r.readUint64OutAt(fileOffset))
	default:
		// Best-effort: if symbol is unresolved, prefer preserving the in-memory pointer.
		if S == 0 {
			if currentVal := r.readUint64OutAt(fileOffset); currentVal != 0 {
				return r.normalizeLoadedAddressValue(currentVal)
			}
		}
		return r.normalizeLoadedAddressValue(S)
	}
}

// computeRelaValue computes the fixed value for a RELA relocation.
func (r *ElfRebuilder) computeRelaValue(rela *Elf64_Rela, fileOffset uint64) uint64 {
	relocType := rela.Type()
	relocSym := rela.Sym()

	var S int64
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.Name))
		r.logger.Debug("rela resolve", "symbol", symName, "type", sym.StType().String(), "bind", sym.StBind().String())
		S = int64(sym.Value)
	}

	A := rela.Addend
	// R_AARCH64_NONE is filtered by isDataRelocation before reaching here.
	if v, ok := r.sharedDataRelocValue(relocType, fileOffset); ok {
		return v
	}
	switch relocType {
	case R_AARCH64_RELATIVE:
		// Result = B + A. With B normalised to 0 the value is simply A.
		return uint64(A)
	default:
		// Best-effort: if symbol is unresolved, preserve the in-memory pointer.
		if S == 0 {
			if currentVal := r.readUint64OutAt(fileOffset); currentVal != 0 {
				return r.normalizeLoadedAddressValue(currentVal)
			}
		}
		return r.normalizeLoadedAddressValue(uint64(S + A))
	}
}

func (r *ElfRebuilder) writeAtOffset(offset uint64, value any) error {
	if _, err := r.OutFile.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	return binary.Write(r.OutFile, binary.LittleEndian, value)
}

func (r *ElfRebuilder) readUint64OutAt(offset uint64) uint64 {
	var buf [8]byte
	n, err := r.OutFile.ReadAt(buf[:], int64(offset))
	if err != nil || n != len(buf) {
		r.logger.Warn("uint64 read_out", "offset", offset, "read_count", n, "error", err)
		return 0
	}
	return binary.LittleEndian.Uint64(buf[:])
}

func (r *ElfRebuilder) relocationTargetOffset(vaddr uint64) (uint64, error) {
	fileOffset, ok := r.vaddrToFileOffset(vaddr)
	if !ok {
		return 0, fmt.Errorf("relocation target 0x%x is outside loadable ranges", vaddr)
	}
	return fileOffset, nil
}

// rebuildFileLayout moves segments to match their virtual addresses in the output file
func (r *ElfRebuilder) rebuildFileLayout() error {
	// Find min and max Vaddr
	var minVaddr uint64 = ^uint64(0)
	var maxVaddr uint64 = 0
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD {
			if phdr.Vaddr < minVaddr {
				minVaddr = phdr.Vaddr
			}
			if phdr.Vaddr+phdr.Memsz > maxVaddr {
				maxVaddr = phdr.Vaddr + phdr.Memsz
			}
		}
	}
	if minVaddr == ^uint64(0) {
		minVaddr = 0
	}

	// Copy segments one by one to handle potential gaps and .bss correctly.
	// Memory dumps may not have data for all virtual address ranges.
	for i := range r.Phdrs {
		p := &r.Phdrs[i]
		if p.Type != PT_LOAD {
			continue
		}

		// Calculate output offset relative to minVaddr
		outOffset := p.Vaddr - minVaddr

		// Write full memory state (p_memsz)
		// This captures .bss and any in-memory modifications
		if p.Memsz > 0 {
			segmentData := make([]byte, p.Memsz)
			readN, err := r.File.ReadAt(segmentData, int64(p.Offset))
			if err != nil {
				r.logger.Warn("relayout read_partial", "index", i, "offset", p.Offset, "memory_size", p.Memsz, "read_count", readN, "error", err)
			}
			if _, err := r.OutFile.WriteAt(segmentData, int64(outOffset)); err != nil {
				return fmt.Errorf("failed to write segment %d data: %w", i, err)
			}
			r.logger.Debug("segment relayout", "index", i, "vaddr", p.Vaddr, "size", p.Memsz, "offset", p.Offset)
		}
	}

	// Update PHDR offsets to match memory layout (Offset = Vaddr - minVaddr).
	// For PT_LOAD we also bump Filesz to Memsz so .bss-style ranges are covered
	// by the residual pointer scan. Other segment types (notably PT_TLS) keep
	// their original Filesz — bumping it there would lie about uninit data.
	for i := range r.Phdrs {
		r.Phdrs[i].Offset = r.Phdrs[i].Vaddr - minVaddr
		if r.Phdrs[i].Type == PT_LOAD {
			r.Phdrs[i].Filesz = r.Phdrs[i].Memsz
		}
		r.logger.Debug("segment relayout", "index", i, "vaddr", r.Phdrs[i].Vaddr, "new_offset", r.Phdrs[i].Offset)
	}

	return nil
}

func (r *ElfRebuilder) patchResidualBasePointers() error {
	if r.BaseAddr == 0 || r.TotalSize == 0 {
		return nil
	}

	patched := map[uint64]struct{}{}
	performCheck := func(start uint64, end uint64) {
		if start >= end {
			return
		}
		for off := start; off+8 <= end; off += 8 {
			if _, contains := patched[off]; contains {
				continue
			}

			val := r.readUint64OutAt(off)
			rebased, ok := r.normalizeLoadedAddress(val)
			if !ok {
				continue
			}

			meaningful, symb := r.isMeaningfulRebasedPointer(rebased)
			if !meaningful {
				continue
			}
			symbName := ""
			if symb != nil {
				symbName = r.readStrtabString(symb.Name)
			}
			if err := r.writeAtOffset(off, rebased); err != nil {
				r.logger.Warn("residual patch", "reason", "failed to patch residual pointer", "offset", off, "error", err)
			}
			patched[off] = struct{}{}
			r.logger.Debug("residual patch", "offset", off, "from", val, "to", rebased, "symbol", symbName)
		}
	}
	for _, phdr := range r.Phdrs {
		// Only writable data segments are safe to scan. Read-only PT_LOAD ranges
		// commonly contain metadata tables where pointer-like words are structure
		// fields, not residual data pointers.
		if phdr.Type != PT_LOAD || (phdr.Flags&PF_W) == 0 {
			continue
		}
		performCheck(phdr.Offset, phdr.Offset+phdr.Filesz)
	}

	r.logger.Info("residual scan", "patched_count", len(patched))
	return nil
}

func (r *ElfRebuilder) isMeaningfulRebasedPointer(v uint64) (bool, *Elf64_Sym) {
	// 1. Inside a PT_LOAD is the strongest signal.
	for _, phdr := range r.Phdrs {
		if phdr.Type != PT_LOAD {
			continue
		}
		if v >= phdr.Vaddr && v < phdr.Vaddr+phdr.Memsz {
			return true, nil
		}
	}

	// 2. Exact symbol / inside symbol is also a good signal.
	for i, sym := range r.Symbols {
		if sym.Value == 0 {
			continue
		}
		if v == sym.Value || (sym.Size != 0 && v > sym.Value && v < sym.Value+sym.Size) {
			return true, &r.Symbols[i]
		}
	}

	// 3. Known metadata ranges.
	ranges := [][2]uint64{
		{r.strtabVaddr, r.strtabVaddr + r.strtabSize},
		{r.symtabVaddr, r.symtabVaddr + r.symCount*sizeofSym},
		{r.relVaddr, r.relVaddr + r.relSize},
		{r.relaVaddr, r.relaVaddr + r.relaSize},
		{r.jmprelVaddr, r.jmprelVaddr + r.jmprelSize},
		{r.dynamicVaddr, r.dynamicVaddr + uint64(len(r.Dyns))*sizeofDyn},
		{r.initArrayVaddr, r.initArrayVaddr + r.initArraySize},
		{r.finiArrayVaddr, r.finiArrayVaddr + r.finiArraySize},
		{r.preinitArrayVaddr, r.preinitArrayVaddr + r.preinitArraySize},
		{r.gotVaddr, r.gotVaddr + r.gotSize},
		{r.pltGotVaddr, r.pltGotVaddr + r.pltGotSize},
		{r.ehFrameHdrVaddr, r.ehFrameHdrVaddr + r.ehFrameHdrSize},
	}
	for _, rr := range ranges {
		if rr[0] != 0 && v >= rr[0] && v < rr[1] {
			return true, nil
		}
	}

	return false, nil
}
