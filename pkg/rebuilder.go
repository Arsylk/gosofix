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
	var rebuilder ElfRebuilder = ElfRebuilder{
		ElfReader: reader,
		OutFile:   nil,

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

	// Fix ELF Header - write normalized Entry address
	if err := r.writeAtOffset(24, r.ElfHeader.Entry); err != nil {
		return fmt.Errorf("failed to write ehdr entry: %w", err)
	}

	// Fix program headers - write the in-memory values back. rebuildFileLayout
	// has already updated Offset and (for PT_LOAD) Filesz; reading from the
	// struct keeps PT_TLS-style segments honest about their uninit portion.
	phdrOffset := r.ElfHeader.PhdrOffset
	for i, phdr := range r.Phdrs {
		offset := phdrOffset + uint64(i)*uint64(r.ElfHeader.Phentsize)
		if err := r.writeAtOffset(offset+8, phdr.Offset); err != nil {
			return fmt.Errorf("failed to write phdr offset %d: %w", phdr.Offset, err)
		}
		if err := r.writeAtOffset(offset+16, phdr.Vaddr); err != nil {
			return fmt.Errorf("failed to write phdr vaddr %d: %w", phdr.Vaddr, err)
		}
		if err := r.writeAtOffset(offset+24, phdr.Vaddr); err != nil {
			return fmt.Errorf("failed to write phdr paddr %d: %w", phdr.Vaddr, err)
		}
		if err := r.writeAtOffset(offset+32, phdr.Filesz); err != nil {
			return fmt.Errorf("failed to write phdr filesz %d: %w", phdr.Filesz, err)
		}
		if err := r.writeAtOffset(offset+40, phdr.Memsz); err != nil {
			return fmt.Errorf("failed to write phdr memsz %d: %w", phdr.Memsz, err)
		}
		r.logger.Debug("phdr write", "index", i, "type", phdr.Type.Text(), "vaddr", phdr.Vaddr, "paddr", phdr.Vaddr, "offset", phdr.Offset, "file_size", phdr.Filesz, "memory_size", phdr.Memsz)
	}
	r.logger.Info("phdrs write", "count", len(r.Phdrs))

	if err := r.writeFixedInitsFinis(); err != nil {
		return fmt.Errorf("failed to write init/fini arrays: %w", err)
	}

	// Apply relocation patches to target addresses (data/GOT)
	if err := r.writeFixedRelocs(); err != nil {
		return fmt.Errorf("failed to write relocs: %w", err)
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

// normalizeValue checks if a value looks like an absolute address in the dump range
// and normalizes it to a relative offset if so.
func (r *ElfRebuilder) normalizeValue(val uint64) uint64 {
	if r.BaseAddr != 0 && val >= r.BaseAddr && val < (r.BaseAddr+r.TotalSize) {
		return val - r.BaseAddr
	}
	return val
}

func (r *ElfRebuilder) writeSectionHeaders() error {
	// Mandatory null section at index 0.
	_ = r.addSection("", SHT_NULL, 0, 0, 0, 0, 0, 0)

	// Track indices for link fields
	var dynstrIdx, dynsymIdx, pltGotIdx int
	var pltRelocName string
	if r.jmprelVaddr != 0 {
		if r.jmprelEntrySize == 16 {
			pltRelocName = ".rel.plt"
		} else {
			pltRelocName = ".rela.plt"
		}
	}

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
		// SHT_RELR entries are 8-byte words (Elf64_Relr).
		knownSections = append(knownSections, sectionInfo{".relr.dyn", SHT_RELR, SHF_ALLOC,
			r.relrVaddr, r.relrSize, 0, 0, 8})
	}
	if r.jmprelVaddr != 0 {
		name := ".rela.plt"
		shType := SHT_RELA
		if r.jmprelEntrySize == 16 {
			name = ".rel.plt"
			shType = SHT_REL
		}
		knownSections = append(knownSections, sectionInfo{name, shType, SHF_ALLOC | SHF_INFO_LINK,
			r.jmprelVaddr, r.jmprelSize, 0, 0, r.jmprelEntrySize})
	}
	if r.dynamicVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
			r.dynamicVaddr, r.dynamicSize, 0, 0, sizeofDyn})
	}
	if r.gotVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
			r.gotVaddr, r.gotSize, 0, 0, 8})
	}
	if r.pltGotVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
			r.pltGotVaddr, r.pltGotSize, 0, 0, 8})
	}
	if r.initArrayVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".init_array", SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.initArrayVaddr, r.initArraySize, 0, 0, 8})
	}
	if r.finiArrayVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".fini_array", SHT_FINI_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.finiArrayVaddr, r.finiArraySize, 0, 0, 8})
	}
	if r.preinitArrayVaddr != 0 {
		knownSections = append(knownSections, sectionInfo{".preinit_array", SHT_PREINIT_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.preinitArrayVaddr, r.preinitArraySize, 0, 0, 8})
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

	// 2. Add deterministic PT_LOAD-backed sections only.
	// These sections represent authoritative memory coverage, not guessed original topology.
	var finalSections []sectionInfo
	finalSections = append(finalSections, knownSections...)

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

	type interval struct {
		start, end uint64
	}

	// nameOccurrence counts how many PT_LOAD segments of each base name (.text/.rw/.ro)
	// we've seen. Used to disambiguate sections from multiple writable/read-only segments.
	nameOccurrence := map[string]int{}

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
			start := ks.addr
			if start < segStart {
				start = segStart
			}
			end := ksEnd
			if end > segEnd {
				end = segEnd
			}
			occupied = append(occupied, interval{start, end})
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
			finalSections = append(finalSections, sectionInfo{
				name:    name,
				shType:  SHT_PROGBITS,
				flags:   loadSectionFlags(phdr),
				addr:    gap.start,
				size:    size,
				entsize: 0,
			})
		}
	}

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
		case SHT_HASH, SHT_GNU_HASH, SHT_GNU_VERSYM, SHT_REL, SHT_RELA:
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

	// e_shoff at offset 40 (8 bytes)
	if err := r.writeAtOffset(40, shdrOffset); err != nil {
		return err
	}
	// e_shentsize at offset 58 (2 bytes)
	eShEntSize := uint16(sizeofShdr)
	if err := r.writeAtOffset(58, eShEntSize); err != nil {
		return err
	}
	// e_shnum at offset 60 (2 bytes)
	eShNum := uint16(len(r.sections))
	if err := r.writeAtOffset(60, eShNum); err != nil {
		return err
	}
	// e_shstrndx at offset 62 (2 bytes)
	eShStrNdx := uint16(shstrtabIdx)
	if err := r.writeAtOffset(62, eShStrNdx); err != nil {
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
		if sym.St_Value == 0 || sym.St_Shndx == 0 {
			continue
		}
		if sym.St_Shndx >= 0xff00 {
			continue
		}
		newShndx := r.findAuthoritativeSectionForAddr(sym.St_Value)
		if newShndx != 0 {
			sym.St_Shndx = newShndx
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

// writeFixedInitsFinis writes addresses for init_array, fini_array & preinit_array
func (r *ElfRebuilder) writeFixedInitsFinis() error {
	// DT_INIT and DT_FINI are already normalized as dynamic tag values
	// in ReadDyns. The values ARE the function addresses — we must not
	// read or modify bytes at those addresses (they contain code, not pointers).

	if r.initArraySize > 0 && r.initArrayVaddr != 0 {
		initArrayCount := r.initArraySize / 8
		for i := range initArrayCount {
			vaddr := r.initArrayVaddr + uint64(i)*8
			fileOffset := r.vaddrToOffset(vaddr)
			value := r.readUint64OutAt(fileOffset)
			newVal := r.normalizeValue(value)
			if newVal != value {
				if err := r.writeAtOffset(fileOffset, newVal); err != nil {
					return fmt.Errorf("failed to write init_array: %w", err)
				}
				r.logger.Debug("init_array write", "index", i, "offset", fileOffset, "value", newVal)
			}
		}
		r.logger.Info("init_array write", "count", initArrayCount)
	}

	if r.finiArraySize > 0 && r.finiArrayVaddr != 0 {
		finiArrayCount := r.finiArraySize / 8
		for i := range finiArrayCount {
			vaddr := r.finiArrayVaddr + uint64(i)*8
			fileOffset := r.vaddrToOffset(vaddr)
			value := r.readUint64OutAt(fileOffset)
			newVal := r.normalizeValue(value)
			if newVal != value {
				if err := r.writeAtOffset(fileOffset, newVal); err != nil {
					return fmt.Errorf("failed to write fini_array: %w", err)
				}
				r.logger.Debug("fini_array write", "index", i, "offset", fileOffset, "value", newVal)
			}
		}
		r.logger.Info("fini_array write", "count", finiArrayCount)
	}

	if r.preinitArraySize > 0 && r.preinitArrayVaddr != 0 {
		preinitArrayCount := r.preinitArraySize / 8
		for i := range preinitArrayCount {
			vaddr := r.preinitArrayVaddr + uint64(i)*8
			fileOffset := r.vaddrToOffset(vaddr)
			value := r.readUint64OutAt(fileOffset)
			newVal := r.normalizeValue(value)
			if newVal != value {
				if err := r.writeAtOffset(fileOffset, newVal); err != nil {
					return fmt.Errorf("failed to write preinit_array: %w", err)
				}
				r.logger.Debug("preinit_array write", "index", i, "offset", fileOffset, "value", newVal)
			}
		}
		r.logger.Info("preinit_array write", "count", preinitArrayCount)
	}

	return nil
}

// writeFixedRelocs writes REL, RELA & JMPREL(A)
func (r *ElfRebuilder) writeFixedRelocs() error {
	// Fix REL relocations - write to target locations
	for i, rel := range r.Rel {
		relocType := rel.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug("rel skip", "index", i, "type", relocType.Text(), "reason", "unsupported_or_none")
			continue
		}
		// rel.Offset is already normalized to relative Vaddr
		targetFileOffset, err := r.relocationTargetOffset(rel.Offset)
		if err != nil {
			return fmt.Errorf("failed to map rel target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelValue(&rel, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rel: %w", err)
		}
		r.logger.Debug("rel write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rel.Type().Text())
	}

	// Fix RELA relocations - write to target locations
	for i, rela := range r.Rela {
		relocType := rela.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug("rela skip", "index", i, "type", relocType.Text(), "reason", "unsupported_or_none")
			continue
		}
		targetFileOffset, err := r.relocationTargetOffset(rela.Offset)
		if err != nil {
			return fmt.Errorf("failed to map rela target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelaValue(&rela, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rela: %w", err)
		}
		r.logger.Debug("rela write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rela.Type().Text())
	}

	// Fix JmpRel relocations - write to target locations
	for i, rel := range r.JmpRel {
		relocType := rel.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug("jmprel skip", "index", i, "type", relocType.Text(), "reason", "unsupported_or_none")
			continue
		}
		targetFileOffset, err := r.relocationTargetOffset(rel.Offset)
		if err != nil {
			return fmt.Errorf("failed to map jmprel target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelValue(&rel, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprel: %w", err)
		}
		r.logger.Debug("jmprel write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rel.Type().Text())
	}

	// Fix JmpRela relocations - write to target locations
	for i, rela := range r.JmpRela {
		relocType := rela.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug("jmprela skip", "index", i, "type", relocType.Text(), "reason", "unsupported_or_none")
			continue
		}
		targetFileOffset, err := r.relocationTargetOffset(rela.Offset)
		if err != nil {
			return fmt.Errorf("failed to map jmprela target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelaValue(&rela, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprela: %w", err)
		}
		r.logger.Debug("jmprela write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rela.Type().Text())
	}

	// Fix Android REL relocations
	for i, rel := range r.AndroidRel {
		relocType := rel.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug("android_rel skip", "index", i, "type", relocType.Text(), "reason", "unsupported_or_none")
			continue
		}
		targetFileOffset, err := r.relocationTargetOffset(rel.Offset)
		if err != nil {
			return fmt.Errorf("failed to map android_rel target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelValue(&rel, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write android_rel: %w", err)
		}
		r.logger.Debug("android_rel write", "index", i, "offset", targetFileOffset, "value", fixedVal)
	}

	// Fix Android RELA relocations
	for i, rela := range r.AndroidRela {
		relocType := rela.Type()
		if !isDataRelocation(relocType) {
			r.logger.Debug("android_rela skip", "index", i, "type", relocType.Text(), "reason", "unsupported_or_none")
			continue
		}
		targetFileOffset, err := r.relocationTargetOffset(rela.Offset)
		if err != nil {
			return fmt.Errorf("failed to map android_rela target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelaValue(&rela, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write android_rela: %w", err)
		}
		r.logger.Debug("android_rela write", "index", i, "offset", targetFileOffset, "value", fixedVal)
	}

	// Fix RELR relocations — all entries are R_AARCH64_RELATIVE
	if len(r.Relr) > 0 {
		var where uint64
		var relrCount int
		for _, entry := range r.Relr {
			if (entry & 1) == 0 {
				// Even entry: absolute offset to patch
				where = entry
				if r.BaseAddr != 0 && where >= r.BaseAddr {
					where -= r.BaseAddr
				}
				if where == 0 {
					// A zero anchor would imply patching the ELF header — almost
					// certainly malformed RELR data. Skip and continue.
					r.logger.Warn("relr skip", "reason", "zero_anchor", "raw_entry", entry)
					where += 8
					continue
				}
				if err := r.patchRelrAt(where); err != nil {
					return err
				}
				relrCount++
				where += 8
			} else {
				// Odd entry: bitmap, each bit covers a pointer-width slot
				for i := uint(0); i < 63; i++ {
					if (entry & (1 << (i + 1))) != 0 {
						if err := r.patchRelrAt(where + uint64(i)*8); err != nil {
							return err
						}
						relrCount++
					}
				}
				where += 63 * 8
			}
		}
		r.logger.Info("relr write", "entries", len(r.Relr), "patched_count", relrCount)
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
	currentVal := r.readUint64OutAt(fileOffset)
	newVal := r.normalizeValue(currentVal)
	if newVal != currentVal {
		if err := r.writeAtOffset(fileOffset, newVal); err != nil {
			return fmt.Errorf("failed to write relr: %w", err)
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
// an 8-byte slot. Code relocations (ADR, CALL26, etc.) modify 4-byte
// instructions and must not be treated as 8-byte writes.
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

// computeRelValue computes the fixed value for a REL relocation.
// REL has no explicit addend — for relocation types that need one, the addend
// is read from the slot at fileOffset (the in-place value).
func (r *ElfRebuilder) computeRelValue(rel *Elf64_Rel, fileOffset uint64) uint64 {
	relocType := rel.Type()
	relocSym := rel.Sym()

	var S uint64
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.St_Name))
		r.logger.Debug("rel resolve", "symbol", symName, "type", sym.StType().Text(), "bind", sym.StBind().Text())
		S = sym.St_Value
	}

	// R_AARCH64_NONE is filtered by isDataRelocation before reaching here.
	switch relocType {
	case R_AARCH64_COPY:
		return r.readUint64OutAt(fileOffset) // preserve in-memory copy
	case R_AARCH64_RELATIVE, R_AARCH64_IRELATIVE:
		// In-place value is base + addend; normalize to leave just the addend.
		return r.normalizeValue(r.readUint64OutAt(fileOffset))
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64:
		return r.normalizeValue(r.readUint64OutAt(fileOffset))
	case R_AARCH64_PREL64:
		// Slot stores S + A - P; for in-module refs that's base-invariant, so
		// normalising the in-place value is a no-op (and avoids guessing P).
		return r.readUint64OutAt(fileOffset)
	case R_AARCH64_TLS_DTPMOD:
		return 1 // Module ID for same module
	case R_AARCH64_TLS_DTPREL, R_AARCH64_TLS_TPREL:
		// Slot stores the in-place addend A; result is S + A.
		return S + r.readUint64OutAt(fileOffset)
	case R_AARCH64_TLSDESC:
		// TLS descriptor: preserve in-place values (resolver pointer + arg).
		return r.readUint64OutAt(fileOffset)
	default:
		// Best-effort: if symbol is unresolved, prefer preserving the in-memory pointer.
		if S == 0 {
			if currentVal := r.readUint64OutAt(fileOffset); currentVal != 0 {
				return r.normalizeValue(currentVal)
			}
		}
		return r.normalizeValue(S)
	}
}

// computeRelaValue computes the fixed value for a RELA relocation.
func (r *ElfRebuilder) computeRelaValue(rela *Elf64_Rela, fileOffset uint64) uint64 {
	relocType := rela.Type()
	relocSym := rela.Sym()

	var S int64
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.St_Name))
		r.logger.Debug("rela resolve", "symbol", symName, "type", sym.StType().Text(), "bind", sym.StBind().Text())
		S = int64(sym.St_Value)
	}

	A := rela.Addend
	// R_AARCH64_NONE is filtered by isDataRelocation before reaching here.
	switch relocType {
	case R_AARCH64_COPY:
		return r.readUint64OutAt(fileOffset) // preserve in-memory copy
	case R_AARCH64_RELATIVE, R_AARCH64_IRELATIVE:
		// Result = B + A. With B normalised to 0 the value is simply A.
		return uint64(A)
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64:
		// For external symbols S is 0 and the slot was populated at runtime
		// with the resolved address; prefer the slot so we don't zero it.
		return r.normalizeValue(r.readUint64OutAt(fileOffset))
	case R_AARCH64_PREL64:
		// S + A - P (P is the virtual address of the location).
		return uint64(S + A - int64(rela.Offset))
	case R_AARCH64_TLS_DTPMOD:
		return 1 // Module ID for same module
	case R_AARCH64_TLS_DTPREL, R_AARCH64_TLS_TPREL:
		return uint64(S + A)
	case R_AARCH64_TLSDESC:
		// Preserve in-place descriptor pair.
		return r.readUint64OutAt(fileOffset)
	default:
		// Best-effort: if symbol is unresolved, preserve the in-memory pointer.
		if S == 0 {
			if currentVal := r.readUint64OutAt(fileOffset); currentVal != 0 {
				return r.normalizeValue(currentVal)
			}
		}
		return r.normalizeValue(uint64(S + A))
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

func (r *ElfRebuilder) mapVaddrToFileOffset(vaddr uint64) (uint64, bool) {
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

func (r *ElfRebuilder) relocationTargetOffset(vaddr uint64) (uint64, error) {
	fileOffset, ok := r.mapVaddrToFileOffset(vaddr)
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
			if val < r.BaseAddr || val >= r.BaseAddr+r.TotalSize {
				continue
			}

			rebased := val - r.BaseAddr
			meaningful, symb := r.isMeaningfulRebasedPointer(rebased)
			if !meaningful {
				continue
			}
			symbName := ""
			if symb != nil {
				symbName = r.readStrtabString(symb.St_Name)
			}
			if err := r.writeAtOffset(off, rebased); err != nil {
				r.logger.Warn("residual patch", "reason", "failed to patch residual pointer", "offset", off, "error", err)
			}
			patched[off] = struct{}{}
			r.logger.Debug("residual patch", "offset", off, "from", val, "to", rebased, "symbol", symbName)
		}
	}
	for _, phdr := range r.Phdrs {
		// Skip executable segments — scanning .text for 8-byte-aligned pointer-like values
		// risks corrupting instruction immediates and literal pool constants.
		if (phdr.Flags & PF_X) != 0 {
			continue
		}
		performCheck(phdr.Offset, phdr.Offset+phdr.Filesz)
	}

	for _, shdr := range r.sections {
		performCheck(shdr.Offset, shdr.Offset+shdr.Size)
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
		if sym.St_Value == 0 {
			continue
		}
		if v == sym.St_Value || (sym.St_Size != 0 && v > sym.St_Value && v < sym.St_Value+sym.St_Size) {
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
