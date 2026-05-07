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

	sections       []Elf64_Shdr
	shstrtab       []byte
	sectionNameMap map[string]uint32
}

func NewElfRebuilder(reader *ElfReader, outputPath string) (*ElfRebuilder, error) {
	var rebuilder ElfRebuilder = ElfRebuilder{
		ElfReader: reader,
		OutFile:   nil,

		sections:       make([]Elf64_Shdr, 0),
		shstrtab:       []byte{0},
		sectionNameMap: make(map[string]uint32),
	}

	var err error
	rebuilder.OutFile, err = os.OpenFile(outputPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.ModePerm)
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

	// Fix program headers - write normalized Vaddr and Offset values
	phdrOffset := r.ElfHeader.PhdrOffset
	for i, phdr := range r.Phdrs {
		offset := phdrOffset + uint64(i)*uint64(r.ElfHeader.Phentsize)
		// Write fixed Offset
		if err := r.writeAtOffset(offset+8, phdr.Offset); err != nil {
			return fmt.Errorf("failed to write phdr offset %d: %w", phdr.Offset, err)
		}
		// Write fixed Vaddr & Paddr
		if err := r.writeAtOffset(offset+16, phdr.Vaddr); err != nil {
			return fmt.Errorf("failed to write phdr vaddr %d: %w", phdr.Vaddr, err)
		}
		if err := r.writeAtOffset(offset+24, phdr.Vaddr); err != nil {
			return fmt.Errorf("failed to write phdr paddr %d: %w", phdr.Vaddr, err)
		}

		// Write same value for Filesz & Memsz to preserve in-memory state
		size := phdr.Memsz
		if err := r.writeAtOffset(offset+32, size); err != nil {
			return fmt.Errorf("failed to write phdr filesz %d: %w", size, err)
		}
		if err := r.writeAtOffset(offset+40, size); err != nil {
			return fmt.Errorf("failed to write phdr memsz %d: %w", size, err)
		}
		logger.Debug("phdr write", "index", i, "type", phdr.Type.Text(), "vaddr", phdr.Vaddr, "paddr", phdr.Vaddr, "offset", phdr.Offset, "file_size", size, "memory_size", size)
	}
	logger.Info("phdrs write", "count", len(r.Phdrs))

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

	// Patch symbol table in place
	r.fixSymbolSectionIndices()
	if err := r.writeSymbolTable(); err != nil {
		return fmt.Errorf("failed to patch symbols: %w", err)
	}

	// Build and write section headers
	if err := r.writeSectionHeaders(); err != nil {
		return fmt.Errorf("failed to write section headers: %w", err)
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
	return offset
}

func (r *ElfRebuilder) readSectionName(nameOffset uint32) string {
	for key, val := range r.sectionNameMap {
		if val == nameOffset {
			return key
		}
	}
	return ""
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
	r.addSection("", SHT_NULL, 0, 0, 0, 0, 0, 0)

	// Track indices for link fields
	var dynstrIdx, dynsymIdx int

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
	if r.strtabOffset != 0 && r.strtabSize != 0 {
		knownSections = append(knownSections, sectionInfo{".dynstr", SHT_STRTAB, SHF_ALLOC,
			r.strtabOffset, r.strtabSize, 0, 0, 0})
	}
	if r.symtabOffset != 0 && r.symCount > 0 {
		symSize := r.symCount * 24
		firstGlobalIdx := uint32(1)
		for i, sym := range r.Symbols {
			if sym.stBind() != STB_LOCAL {
				firstGlobalIdx = uint32(i)
				break
			}
		}
		knownSections = append(knownSections, sectionInfo{".dynsym", SHT_DYNSYM, SHF_ALLOC,
			r.symtabOffset, symSize, 0, firstGlobalIdx, 24})
	}
	if r.hashOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".hash", SHT_HASH, SHF_ALLOC,
			r.hashOffset, r.hashSize, 0, 0, 4})
	}
	if r.gnuHashOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".gnu.hash", SHT_GNU_HASH, SHF_ALLOC,
			r.gnuHashOffset, r.gnuHashSize, 0, 0, 0})
	}
	if r.versymOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".gnu.version", SHT_GNU_VERSYM, SHF_ALLOC,
			r.versymOffset, r.symCount * 2, 0, 0, 2})
	}
	if r.verneedOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".gnu.version_r", SHT_GNU_VERNEED, SHF_ALLOC,
			r.verneedOffset, r.verneedSize, 0, uint32(r.verneedNum), 0})
	}
	if r.relaOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".rela.dyn", SHT_RELA, SHF_ALLOC,
			r.relaOffset, r.relaSize, 0, 0, 24})
	}
	if r.relOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".rel.dyn", SHT_REL, SHF_ALLOC,
			r.relOffset, r.relSize, 0, 0, 16})
	}
	if r.jmprelOffset != 0 {
		name := ".rela.plt"
		shType := SHT_RELA
		if r.jmprelEntrySize == 16 {
			name = ".rel.plt"
			shType = SHT_REL
		}
		knownSections = append(knownSections, sectionInfo{name, shType, SHF_ALLOC | SHF_INFO_LINK,
			r.jmprelOffset, r.jmprelSize, 0, 0, r.jmprelEntrySize})
	}
	if r.dynamicOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
			r.dynamicOffset, r.dynamicSize, 0, 0, 16})
	}
	if r.gotOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
			r.gotOffset, r.gotSize, 0, 0, 8})
	}
	if r.pltGotOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
			r.pltGotOffset, r.pltGotSize, 0, 0, 8})
	}
	if r.initArrayOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".init_array", SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.initArrayOffset, r.initArraySize, 0, 0, 8})
	}
	if r.finiArrayOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".fini_array", SHT_FINI_ARRAY, SHF_ALLOC | SHF_WRITE,
			r.finiArrayOffset, r.finiArraySize, 0, 0, 8})
	}

	// Add additional metadata found in program headers
	if r.ehFrameHdrOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".eh_frame_hdr", SHT_PROGBITS, SHF_ALLOC,
			r.ehFrameHdrOffset, r.ehFrameHdrSize, 0, 0, 4})
	}
	if r.noteOffset != 0 {
		knownSections = append(knownSections, sectionInfo{".note.gnu.build-id", SHT_NOTE, SHF_ALLOC,
			r.noteOffset, r.noteSize, 0, 0, 4})
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

		// Add knownSections
		for _, ks := range knownSections {
			ksEnd := ks.addr + ks.size
			if ks.addr >= phdr.Vaddr && ks.addr < phdr.Vaddr+phdr.Memsz {
				occupied = append(occupied, interval{ks.addr, ksEnd})
			} else if ksEnd > phdr.Vaddr && ksEnd <= phdr.Vaddr+phdr.Memsz {
				occupied = append(occupied, interval{ks.addr, ksEnd})
			}
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
			name := loadSectionName(phdr)
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
		}
	}

	// 4. Update link fields
	for i := 1; i < len(r.sections); i++ {
		sec := &r.sections[i]
		switch sec.Type {
		case SHT_DYNSYM:
			sec.Link = uint32(dynstrIdx)
		case SHT_HASH, SHT_GNU_HASH, SHT_GNU_VERSYM, SHT_REL, SHT_RELA:
			sec.Link = uint32(dynsymIdx)
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
		offset := shdrOffset + uint64(i)*uint64(binary.Size(Elf64_Shdr{}))
		if err := r.writeAtOffset(offset, &section); err != nil {
			return err
		}
		logger.Info("shdr write", "index", i, "addr", section.Addr, "size", section.Size, "name", r.readSectionName(section.Name))
	}

	// e_shoff at offset 40 (8 bytes)
	if err := r.writeAtOffset(40, shdrOffset); err != nil {
		return err
	}
	// e_shentsize at offset 58 (2 bytes)
	eShEntSize := uint16(binary.Size(Elf64_Shdr{}))
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
	logger.Info("ehdr write", "section_header_offset", shdrOffset, "section_count", eShNum, "shstr_index", eShStrNdx)

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

// writeFixedInitsFinis writes addresses for init_array & finit_array
func (r *ElfRebuilder) writeFixedInitsFinis() error {
	if r.initOffset != 0 {
		fileOffset := r.vaddrToOffset(r.initOffset)
		value := r.readUint64OutAt(fileOffset)
		newVal := r.normalizeValue(value)
		if newVal != value {
			if err := r.writeAtOffset(fileOffset, newVal); err != nil {
				return fmt.Errorf("failed to write init: %w", err)
			}
			logger.Debug("init write", "offset", fileOffset, "value", newVal)
		}
	}

	if r.finiOffset != 0 {
		fileOffset := r.vaddrToOffset(r.finiOffset)
		value := r.readUint64OutAt(fileOffset)
		newVal := r.normalizeValue(value)
		if newVal != value {
			if err := r.writeAtOffset(fileOffset, newVal); err != nil {
				return fmt.Errorf("failed to write fini: %w", err)
			}
			logger.Debug("fini write", "offset", fileOffset, "value", newVal)
		}
	}

	if r.initArraySize > 0 && r.initArrayOffset != 0 {
		initArrayCount := r.initArraySize / 8
		for i := range initArrayCount {
			vaddr := r.initArrayOffset + uint64(i)*8
			fileOffset := r.vaddrToOffset(vaddr)
			value := r.readUint64OutAt(fileOffset)
			newVal := r.normalizeValue(value)
			if newVal != value {
				if err := r.writeAtOffset(fileOffset, newVal); err != nil {
					return fmt.Errorf("failed to write init_array: %w", err)
				}
				logger.Debug("init_array write", "index", i, "offset", fileOffset, "value", newVal)
			}
		}
		logger.Info("init_array write", "count", initArrayCount)
	}

	if r.finiArraySize > 0 && r.finiArrayOffset != 0 {
		finiArrayCount := r.finiArraySize / 8
		for i := range finiArrayCount {
			vaddr := r.finiArrayOffset + uint64(i)*8
			fileOffset := r.vaddrToOffset(vaddr)
			value := r.readUint64OutAt(fileOffset)
			newVal := r.normalizeValue(value)
			if newVal != value {
				if err := r.writeAtOffset(fileOffset, newVal); err != nil {
					return fmt.Errorf("failed to write fini_array: %w", err)
				}
				logger.Debug("fini_array write", "index", i, "offset", fileOffset, "value", newVal)
			}
		}
		logger.Info("fini_array write", "count", finiArrayCount)
	}

	return nil
}

// writeFixedRelocs writes REL, RELA & JMPREL(A)
func (r *ElfRebuilder) writeFixedRelocs() error {
	// Fix REL relocations - write to target locations
	for i, rel := range r.Rel {
		// rel.Offset is already normalized to relative Vaddr
		targetFileOffset, err := r.relocationTargetOffset(rel.Offset)
		if err != nil {
			return fmt.Errorf("failed to map rel target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelValue(&rel, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rel: %w", err)
		}
		logger.Debug("rel write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rel.Type().Text())
	}

	// Fix RELA relocations - write to target locations
	for i, rela := range r.Rela {
		targetFileOffset, err := r.relocationTargetOffset(rela.Offset)
		if err != nil {
			return fmt.Errorf("failed to map rela target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelaValue(&rela, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rela: %w", err)
		}
		logger.Debug("rela write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rela.Type().Text())
	}

	// Fix JmpRel relocations - write to target locations
	for i, rel := range r.JmpRel {
		targetFileOffset, err := r.relocationTargetOffset(rel.Offset)
		if err != nil {
			return fmt.Errorf("failed to map jmprel target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelValue(&rel, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprel: %w", err)
		}
		logger.Debug("jmprel write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rel.Type().Text())
	}

	// Fix JmpRela relocations - write to target locations
	for i, rela := range r.JmpRela {
		targetFileOffset, err := r.relocationTargetOffset(rela.Offset)
		if err != nil {
			return fmt.Errorf("failed to map jmprela target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelaValue(&rela, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprela: %w", err)
		}
		logger.Debug("jmprela write", "index", i, "offset", targetFileOffset, "value", fixedVal, "type", rela.Type().Text())
	}

	// Fix Android REL relocations
	for i, rel := range r.AndroidRel {
		targetFileOffset, err := r.relocationTargetOffset(rel.Offset)
		if err != nil {
			return fmt.Errorf("failed to map android_rel target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelValue(&rel, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write android_rel: %w", err)
		}
		logger.Debug("android_rel write", "index", i, "offset", targetFileOffset, "value", fixedVal)
	}

	// Fix Android RELA relocations
	for i, rela := range r.AndroidRela {
		targetFileOffset, err := r.relocationTargetOffset(rela.Offset)
		if err != nil {
			return fmt.Errorf("failed to map android_rela target at idx %d: %w", i, err)
		}
		fixedVal := r.computeRelaValue(&rela, targetFileOffset)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write android_rela: %w", err)
		}
		logger.Debug("android_rela write", "index", i, "offset", targetFileOffset, "value", fixedVal)
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
		logger.Info("relr write", "entries", len(r.Relr), "patched_count", relrCount)
	}

	logger.Info("relocs write", "count", len(r.Rel)+len(r.Rela)+len(r.JmpRel)+len(r.JmpRela)+len(r.AndroidRel)+len(r.AndroidRela))

	return nil
}

// patchRelrAt patches a single RELR location by subtracting base from the stored value
func (r *ElfRebuilder) patchRelrAt(vaddr uint64) error {
	fileOffset, err := r.relocationTargetOffset(vaddr)
	if err != nil {
		return err
	}
	currentVal := r.readUint64OutAt(fileOffset)
	if r.BaseAddr != 0 && currentVal >= r.BaseAddr {
		newVal := currentVal - r.BaseAddr
		if err := r.writeAtOffset(fileOffset, newVal); err != nil {
			return fmt.Errorf("failed to write relr: %w", err)
		}
	}
	return nil
}

// writeSymbolTable patches the existing symbol table in the file
func (r *ElfRebuilder) writeSymbolTable() error {
	if r.symtabOffset == 0 || len(r.Symbols) == 0 {
		return nil
	}

	symtabFileOffset := r.vaddrToOffset(r.symtabOffset)
	// Write the entire symbol table back to the file
	if err := r.writeAtOffset(symtabFileOffset, r.Symbols); err != nil {
		return fmt.Errorf("failed to write symbol table: %w", err)
	}

	logger.Info("syms write", "count", len(r.Symbols))
	return nil
}

// writeDynamicSection patches the existing dynamic section in the file
func (r *ElfRebuilder) writeDynamicSection() error {
	if r.dynamicOffset == 0 || len(r.Dyns) == 0 {
		return nil
	}

	dynamicFileOffset := r.vaddrToOffset(r.dynamicOffset)
	// Write the entire dynamic section back to the file
	if err := r.writeAtOffset(dynamicFileOffset, r.Dyns); err != nil {
		return fmt.Errorf("failed to write dynamic section: %w", err)
	}

	logger.Info("dyns write", "count", len(r.Dyns))
	return nil
}

func isNullPlaceholderSymbol(sym Elf64_Sym) bool {
	return sym.St_Name == 0 &&
		sym.St_Value == 0 &&
		sym.St_Size == 0 &&
		sym.St_Info == 0 &&
		sym.St_Other == 0 &&
		sym.St_Shndx == 0
}

// computeRelValue computes the fixed value for a REL relocation
func (r *ElfRebuilder) computeRelValue(rel *Elf64_Rel, fileOffset uint64) uint64 {
	relocType := rel.Type()
	relocSym := rel.Sym()

	var S uint64
	useSymIndexAsValue := false
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.St_Name))
		logger.Debug("rel resolve", "symbol", symName, "type", sym.stType().Text(), "bind", sym.stBind().Text())
		S = sym.St_Value
		if isNullPlaceholderSymbol(sym) && relocSym != 0 {
			useSymIndexAsValue = true
		}
	}

	switch relocType {
	case R_AARCH64_NONE:
		return 0
	case R_AARCH64_COPY:
		return r.readUint64OutAt(fileOffset) // preserve in-memory copy
	case R_AARCH64_RELATIVE:
		currentVal := r.readUint64OutAt(fileOffset)
		return r.normalizeValue(currentVal)
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64:
		if useSymIndexAsValue {
			return uint64(relocSym)
		}
		currentVal := r.readUint64OutAt(fileOffset)
		return r.normalizeValue(currentVal)
	case R_AARCH64_TLS_DTPMOD:
		return 1 // Module ID for same module
	case R_AARCH64_TLS_DTPREL:
		return S // TLS offset
	default:
		// Best-effort: if symbol is unresolved, prefer preserving the in-memory pointer.
		if S == 0 {
			currentVal := r.readUint64OutAt(fileOffset)
			if currentVal != 0 {
				return r.normalizeValue(currentVal)
			}
		}
		return r.normalizeValue(S)
	}
}

// computeRelaValue computes the fixed value for a RELA relocation
func (r *ElfRebuilder) computeRelaValue(rela *Elf64_Rela, fileOffset uint64) uint64 {
	relocType := rela.Type()
	relocSym := rela.Sym()

	// Keep S as int64 for proper signed arithmetic with addend
	var S int64
	useSymIndexAsValue := false
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.St_Name))
		logger.Debug("rela resolve", "symbol", symName, "type", sym.stType().Text(), "bind", sym.stBind().Text())
		S = int64(sym.St_Value)
		if isNullPlaceholderSymbol(sym) && relocSym != 0 {
			useSymIndexAsValue = true
		}
	}

	A := rela.Addend // Keep as int64
	switch relocType {
	case R_AARCH64_NONE:
		return uint64(A)
	case R_AARCH64_COPY:
		return r.readUint64OutAt(fileOffset) // preserve in-memory copy
	case R_AARCH64_RELATIVE:
		currentVal := r.readUint64OutAt(fileOffset)
		return r.normalizeValue(currentVal)
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64:
		if useSymIndexAsValue {
			return uint64(int64(relocSym) + A)
		}
		currentVal := r.readUint64OutAt(fileOffset)
		return r.normalizeValue(currentVal)
	case R_AARCH64_PREL64:
		// S + A - P (where P is the virtual address of the location)
		return uint64(int64(S) + A - int64(rela.Offset))
	case R_AARCH64_TLS_DTPMOD:
		return 1 // Module ID for same module
	case R_AARCH64_TLS_DTPREL:
		return uint64(S + A) // TLS offset
	default:
		// Best-effort: if symbol is unresolved, preserve the in-memory pointer.
		if S == 0 {
			currentVal := r.readUint64OutAt(fileOffset)
			if currentVal != 0 {
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
		logger.Warn("uint64 read_out", "offset", offset, "read_count", n, "error", err)
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
				logger.Warn("relayout read_partial", "index", i, "offset", p.Offset, "memory_size", p.Memsz, "read_count", readN, "error", err)
			}
			if _, err := r.OutFile.WriteAt(segmentData, int64(outOffset)); err != nil {
				return fmt.Errorf("failed to write segment %d data: %w", i, err)
			}
			logger.Debug("segment relayout", "index", i, "vaddr", p.Vaddr, "size", p.Memsz, "offset", p.Offset)
		}
	}

	// Update all PHDR offsets to match memory layout (Offset = Vaddr - minVaddr)
	for i := range r.Phdrs {
		r.Phdrs[i].Offset = r.Phdrs[i].Vaddr - minVaddr
		logger.Debug("segment relayout", "index", i, "vaddr", r.Phdrs[i].Vaddr, "new_offset", r.Phdrs[i].Offset)
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

			val := r.ElfReader.readUint64At(off)
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
				logger.Warn("residual patch", "reason", "failed to patch residual pointer", "offset", off, "error", err)
			}
			patched[off] = struct{}{}
			logger.Debug("residual patch", "offset", off, "from", val, "to", rebased, "symbol", symbName)
		}
	}
	for _, phdr := range r.Phdrs {
		performCheck(phdr.Offset, phdr.Offset+phdr.Filesz)
	}

	for _, shdr := range r.sections {
		performCheck(shdr.Offset, shdr.Offset+shdr.Size)
	}

	logger.Info("residual scan", "patched_count", len(patched))
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
		{r.strtabOffset, r.strtabOffset + r.strtabSize},
		{r.symtabOffset, r.symtabOffset + r.symCount*24},
		{r.relOffset, r.relOffset + r.relSize},
		{r.relaOffset, r.relaOffset + r.relaSize},
		{r.jmprelOffset, r.jmprelOffset + r.jmprelSize},
		{r.dynamicOffset, r.dynamicOffset + uint64(len(r.Dyns))*16},
		{r.initArrayOffset, r.initArrayOffset + r.initArraySize},
		{r.finiArrayOffset, r.finiArrayOffset + r.finiArraySize},
		{r.preinitArrayOffset, r.preinitArrayOffset + r.preinitArraySize},
		{r.gotOffset, r.gotOffset + r.gotSize},
		{r.pltGotOffset, r.pltGotOffset + r.pltGotSize},
		{r.ehFrameHdrOffset, r.ehFrameHdrOffset + r.ehFrameHdrSize},
		{r.tlsOffset, r.tlsOffset + r.tlsSize},
	}
	for _, rr := range ranges {
		if rr[0] != 0 && v >= rr[0] && v < rr[1] {
			return true, nil
		}
	}

	return false, nil
}
