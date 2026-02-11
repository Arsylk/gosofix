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
	OutFile *os.File

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

		// Write same value for Filesz & Memsz
		size := max(phdr.Filesz, phdr.Memsz)
		if err := r.writeAtOffset(offset+32, size); err != nil {
			return fmt.Errorf("failed to write phdr filesz %d: %w", size, err)
		}
		if err := r.writeAtOffset(offset+40, size); err != nil {
			return fmt.Errorf("failed to write phdr memsz %d: %w", size, err)
		}
		logger.Debug("phdr:write", "idx", i, "type", phdr.Type.Text(), "vaddr", phdr.Vaddr, "paddr", phdr.Vaddr, "offset", phdr.Offset, "filesz", size, "memsz", size)
	}
	logger.Info("phdrs:write", "count", len(r.Phdrs))

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

		// PLT section header - in memory dumps, PLT is usually right after the last metadata in the first segment
		// or at a fixed location. For libBlackWhiteCrash.so, it's at 0x3bbb30 in a DIFFERENT segment (Segment 2).
		// Our heuristic should try to find where PLT actually resides if possible.
		pltSize := uint64(32) + (r.jmprelSize/r.jmprelEntrySize)*16
		pltAddr := AlignUp(r.jmprelOffset+r.jmprelSize, 16)

		// Check if this calculated PLT address actually lands in an executable segment.
		isExec := false
		for _, phdr := range r.Phdrs {
			if phdr.Type == PT_LOAD && (phdr.Flags&PF_X) != 0 {
				if pltAddr >= phdr.Vaddr && pltAddr < phdr.Vaddr+phdr.Memsz {
					isExec = true
					break
				}
			}
		}

		if !isExec {
			// If our heuristic failed, try looking for the PLT in the first executable segment.
			// In many Android libraries, .plt is at the start or end of the executable segment.
			for _, phdr := range r.Phdrs {
				if phdr.Type == PT_LOAD && (phdr.Flags&PF_X) != 0 {
					pltAddr = phdr.Vaddr + phdr.Memsz - pltSize
					isExec = true
					break
				}
			}
		}

		if isExec {
			knownSections = append(knownSections, sectionInfo{".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
				pltAddr, pltSize, 0, 0, 16})
		}
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

	// 2. Identify the largest gap in each PT_LOAD segment and name it .text/.data
	var finalSections []sectionInfo
	finalSections = append(finalSections, knownSections...)

	for _, phdr := range r.Phdrs {
		if phdr.Type != PT_LOAD || phdr.Memsz == 0 {
			continue
		}

		segStart := phdr.Vaddr
		segEnd := phdr.Vaddr + phdr.Memsz

		// Find largest unused gap in this segment
		var ranges []struct{ start, end uint64 }
		ranges = append(ranges, struct{ start, end uint64 }{segStart, segEnd})

		for _, s := range knownSections {
			if s.addr >= segStart && s.addr < segEnd {
				sEnd := s.addr + s.size
				var nextRanges []struct{ start, end uint64 }
				for _, r := range ranges {
					if s.addr < r.end && sEnd > r.start {
						// Overlap, split range
						if s.addr > r.start {
							nextRanges = append(nextRanges, struct{ start, end uint64 }{r.start, s.addr})
						}
						if sEnd < r.end {
							nextRanges = append(nextRanges, struct{ start, end uint64 }{sEnd, r.end})
						}
					} else {
						nextRanges = append(nextRanges, r)
					}
				}
				ranges = nextRanges
			}
		}

		if len(ranges) > 0 {
			// Determine base name and flags based on segment type
			baseName := ".text"
			var baseFlags uint64 = SHF_ALLOC
			if (phdr.Flags & PF_X) != 0 {
				baseFlags |= SHF_EXECINSTR
			} else if (phdr.Flags & PF_W) != 0 {
				baseName = ".data"
				// Check if this segment is RELRO
				for _, p := range r.Phdrs {
					if p.Type == PT_GNU_RELRO && p.Vaddr == phdr.Vaddr {
						baseName = ".data.rel.ro"
						break
					}
				}
				baseFlags |= SHF_WRITE
			} else {
				baseName = ".rodata"
			}

			// Add ALL gaps as sections, not just the largest
			gapCount := 0
			for _, gap := range ranges {
				gapSize := gap.end - gap.start
				if gapSize > 0 {
					name := baseName
					if gapCount > 0 {
						name = fmt.Sprintf("%s_%d", baseName, gapCount)
					}
					finalSections = append(finalSections, sectionInfo{name, SHT_PROGBITS, baseFlags, gap.start, gapSize, 0, 0, 0})
					gapCount++
				}
			}
		}
	}

	// 3. Add all sections to the rebuilder, sorted by address
	sort.Slice(finalSections, func(i, j int) bool { return finalSections[i].addr < finalSections[j].addr })

	// Dedup and add
	var lastAddr uint64 = 0
	for _, s := range finalSections {
		if s.addr < lastAddr {
			continue
		} // Skip if overlaps (shouldn't happen with gap logic)
		idx := r.addSection(s.name, s.shType, s.flags, s.addr, s.size, s.link, s.info, s.entsize)
		switch s.name {
		case ".dynstr":
			dynstrIdx = idx
		case ".dynsym":
			dynsymIdx = idx
		}
		lastAddr = s.addr + s.size
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
		logger.Info("shdr:write", "idx", i, "addr", section.Addr, "size", section.Size, "name", r.readSectionName(section.Name))
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
	logger.Info("ehdr:write", "e_shoff", shdrOffset, "e_shnum", eShNum, "e_shstrndx", eShStrNdx)

	return nil
}

// fixSymbolSectionIndices determines correct section indices for symbols
func (r *ElfRebuilder) fixSymbolSectionIndices() {
	for i := range r.Symbols {
		sym := &r.Symbols[i]
		if sym.St_Value == 0 || sym.St_Shndx == 0 {
			continue
		}
		// Skip special section indices
		if sym.St_Shndx >= 0xff00 {
			continue
		}
		newShndx := r.findSectionForAddr(sym.St_Value)
		if newShndx != sym.St_Shndx && newShndx != 0 {
			sym.St_Shndx = newShndx
		}
	}
}

// findSectionForAddr finds the section index that contains the given address
func (r *ElfRebuilder) findSectionForAddr(addr uint64) uint16 {
	bestIdx := uint16(0)
	var minSize uint64 = ^uint64(0)
	for i, sec := range r.sections {
		if sec.Type == SHT_NULL || sec.Addr == 0 {
			continue
		}
		if addr >= sec.Addr && addr < sec.Addr+sec.Size {
			if sec.Size < minSize {
				minSize = sec.Size
				bestIdx = uint16(i)
			}
		}
	}
	return bestIdx
}

// writeFixedInitsFinis writes addresses for init_array & finit_array
func (r *ElfRebuilder) writeFixedInitsFinis() error {
	if r.initOffset != 0 {
		fileOffset := r.vaddrToOffset(r.initOffset)
		value := r.readUint64At(fileOffset)
		if value > r.BaseAddr {
			newVal := value - r.BaseAddr
			if err := r.writeAtOffset(fileOffset, newVal); err != nil {
				return fmt.Errorf("failed to write init: %w", err)
			}
			logger.Debug("init:write", "offset", fileOffset, "val", newVal)
		}
	}

	if r.finiOffset != 0 {
		fileOffset := r.vaddrToOffset(r.finiOffset)
		value := r.readUint64At(fileOffset)
		if value > r.BaseAddr {
			newVal := value - r.BaseAddr
			if err := r.writeAtOffset(fileOffset, newVal); err != nil {
				return fmt.Errorf("failed to write fini: %w", err)
			}
			logger.Debug("fini:write", "offset", fileOffset, "val", newVal)
		}
	}

	if r.initArraySize > 0 && r.initArrayOffset != 0 {
		initArrayCount := r.initArraySize / 8
		for i := range initArrayCount {
			vaddr := r.initArrayOffset + uint64(i)*8
			fileOffset := r.vaddrToOffset(vaddr)
			value := r.readUint64At(fileOffset)
			if value > r.BaseAddr {
				newVal := value - r.BaseAddr
				if err := r.writeAtOffset(fileOffset, newVal); err != nil {
					return fmt.Errorf("failed to write init_array: %w", err)
				}
				logger.Debug("init_array:write", "idx", i, "offset", fileOffset, "val", newVal)
			}
		}
		logger.Info("init_array:write", "count", initArrayCount)
	}

	if r.finiArraySize > 0 && r.finiArrayOffset != 0 {
		finiArrayCount := r.finiArraySize / 8
		for i := range finiArrayCount {
			vaddr := r.finiArrayOffset + uint64(i)*8
			fileOffset := r.vaddrToOffset(vaddr)
			value := r.readUint64At(fileOffset)
			if value > r.BaseAddr {
				newVal := value - r.BaseAddr
				if err := r.writeAtOffset(fileOffset, newVal); err != nil {
					return fmt.Errorf("failed to write fini_array: %w", err)
				}
				logger.Debug("fini_array:write", "idx", i, "offset", fileOffset, "val", newVal)
			}
		}
		logger.Info("fini_array:write", "count", finiArrayCount)
	}

	return nil
}

// writeFixedRelocs writes REL, RELA & JMPREL(A)
func (r *ElfRebuilder) writeFixedRelocs() error {
	// Fix REL relocations - write to target locations
	for i, rel := range r.Rel {
		// rel.Offset is already normalized to relative Vaddr
		targetFileOffset := r.vaddrToOffset(rel.Offset)
		fixedVal := r.computeRelValue(&rel)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rel: %w", err)
		}
		logger.Debug("rel:write", "idx", i, "offset", targetFileOffset, "val", fixedVal, "type", rel.Type().Text())
	}

	// Fix RELA relocations - write to target locations
	for i, rela := range r.Rela {
		targetFileOffset := r.vaddrToOffset(rela.Offset)
		fixedVal := r.computeRelaValue(&rela)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rela: %w", err)
		}
		logger.Debug("rela:write", "idx", i, "offset", targetFileOffset, "val", fixedVal, "type", rela.Type().Text())
	}

	// Fix JmpRel relocations - write to target locations
	for i, rel := range r.JmpRel {
		targetFileOffset := r.vaddrToOffset(rel.Offset)
		fixedVal := r.computeRelValue(&rel)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprel: %w", err)
		}
		logger.Debug("jmprel:write", "idx", i, "offset", targetFileOffset, "val", fixedVal, "type", rel.Type().Text())
	}

	// Fix JmpRela relocations - write to target locations
	for i, rela := range r.JmpRela {
		targetFileOffset := r.vaddrToOffset(rela.Offset)
		fixedVal := r.computeRelaValue(&rela)
		if err := r.writeAtOffset(targetFileOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprela: %w", err)
		}
		logger.Debug("jmprela:write", "idx", i, "offset", targetFileOffset, "val", fixedVal, "type", rela.Type().Text())
	}

	logger.Info("relocs:write", "count", len(r.Rel)+len(r.Rela)+len(r.JmpRel)+len(r.JmpRela))

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

	logger.Info("syms:write", "count", len(r.Symbols))
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

	logger.Info("dyns:write", "count", len(r.Dyns))
	return nil
}

// computeRelValue computes the fixed value for a REL relocation
func (r *ElfRebuilder) computeRelValue(rel *Elf64_Rel) uint64 {
	relocType := rel.Type()
	relocSym := rel.Sym()

	var S uint64
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.St_Name))
		logger.Debug("rel:resolve", "sym", symName, "type", sym.stType().Text(), "bind", sym.stBind().Text())
		S = sym.St_Value
	}

	fileOffset := r.vaddrToOffset(rel.Offset)

	switch relocType {
	case R_AARCH64_NONE:
		return 0
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT:
		return S
	case R_AARCH64_RELATIVE:
		// For RELATIVE: the stored value is base + original.
		// We only subtract base if it looks like it contains an absolute address from this dump.
		currentVal := r.readUint64At(fileOffset)
		if r.BaseAddr != 0 && currentVal >= r.BaseAddr {
			return currentVal - r.BaseAddr
		}
		return currentVal
	case R_AARCH64_TLS_DTPMOD:
		return 1 // Module ID for same module
	case R_AARCH64_TLS_DTPREL:
		return S // TLS offset
	default:
		return S
	}
}

// computeRelaValue computes the fixed value for a RELA relocation
func (r *ElfRebuilder) computeRelaValue(rela *Elf64_Rela) uint64 {
	relocType := rela.Type()
	relocSym := rela.Sym()

	// Keep S as int64 for proper signed arithmetic with addend
	var S int64
	if relocSym < uint32(len(r.Symbols)) {
		sym := r.Symbols[relocSym]
		symName := DemangleSymbol(r.readStrtabString(sym.St_Name))
		logger.Debug("rela:resolve", "sym", symName, "type", sym.stType().Text(), "bind", sym.stBind().Text())
		S = int64(sym.St_Value)
	}

	A := rela.Addend // Keep as int64
	// rela.Offset is already normalized (relative Vaddr, not absolute address)
	fileOffset := r.vaddrToOffset(rela.Offset)

	switch relocType {
	case R_AARCH64_NONE:
		return uint64(A)
	case R_AARCH64_RELATIVE:
		// For memory dumps: location contains (BaseAddr + A).
		// We only subtract base if it looks like it contains an absolute address from this dump.
		currentVal := r.readUint64At(fileOffset)
		if r.BaseAddr != 0 && currentVal >= r.BaseAddr {
			return currentVal - r.BaseAddr
		}
		return currentVal
	case R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT:
		return uint64(S + A)
	case R_AARCH64_ABS64:
		return uint64(S + A)
	case R_AARCH64_PREL64:
		// L = location address for PC-relative
		L := int64(fileOffset)
		return uint64(S + A - L)
	case R_AARCH64_TLS_DTPMOD:
		return 1 // Module ID for same module
	case R_AARCH64_TLS_DTPREL:
		return uint64(S + A) // TLS offset
	default:
		return uint64(S + A)
	}
}

func (r *ElfRebuilder) writeAtOffset(offset uint64, value any) error {
	if _, err := r.OutFile.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	return binary.Write(r.OutFile, binary.LittleEndian, value)
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

	// Copy the entire range from minVaddr to maxVaddr from the source file.
	// This preserves all code and data in gaps between segments (like PLTs).
	totalSize := maxVaddr - minVaddr
	data := make([]byte, totalSize)
	_, err := r.File.ReadAt(data, int64(minVaddr))
	if err != nil {
		// If reading the whole range fails (e.g. dump is partial), fall back to segment-by-segment
		logger.Warn("relayout:full_read_failed", "error", err, "msg", "falling back to segment-by-segment copy")
		for i := range r.Phdrs {
			p := &r.Phdrs[i]
			if p.Type != PT_LOAD || p.Filesz == 0 {
				continue
			}
			segmentData := make([]byte, p.Filesz)
			if _, err := r.File.ReadAt(segmentData, int64(p.Offset)); err == nil {
				r.OutFile.WriteAt(segmentData, int64(p.Vaddr-minVaddr))
			}
		}
	} else {
		_, err = r.OutFile.WriteAt(data, 0)
		if err != nil {
			return fmt.Errorf("failed to write expanded layout: %w", err)
		}
	}

	// Update all PHDR offsets to match memory layout (Offset = Vaddr - minVaddr)
	for i := range r.Phdrs {
		r.Phdrs[i].Offset = r.Phdrs[i].Vaddr - minVaddr
		logger.Debug("segment:relayout", "idx", i, "vaddr", r.Phdrs[i].Vaddr, "new_offset", r.Phdrs[i].Offset)
	}

	return nil
}
