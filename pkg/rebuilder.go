package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// ElfRebuilder handles the reconstruction of a valid ELF file
type ElfRebuilder struct {
	reader *ElfReader

	// Section data
	sections    []Elf64_Shdr
	sectionData map[int][]byte

	// Layout information
	currentOffset uint64

	// Section indices
	nullSectionIdx      int
	dynstrSectionIdx    int
	dynsymSectionIdx    int
	hashSectionIdx      int
	gnuHashSectionIdx   int
	dynamicSectionIdx   int
	relSectionIdx       int
	relaSectionIdx      int
	pltRelSectionIdx    int
	gotSectionIdx       int
	initArraySectionIdx int
	finiArraySectionIdx int
	shstrtabSectionIdx  int

	// Section header string table
	shstrtab    []byte
	shstrtabMap map[string]uint32
}

// NewElfRebuilder creates a new ELF rebuilder
func NewElfRebuilder(reader *ElfReader) *ElfRebuilder {
	return &ElfRebuilder{
		reader:      reader,
		sections:    make([]Elf64_Shdr, 0),
		sectionData: make(map[int][]byte),
		shstrtabMap: make(map[string]uint32),
		shstrtab:    []byte{0}, // Start with null byte
	}
}

// addShstrtabString adds a string to the section header string table
func (rb *ElfRebuilder) addShstrtabString(s string) uint32 {
	if s == "" {
		return 0
	}
	if offset, ok := rb.shstrtabMap[s]; ok {
		return offset
	}
	offset := uint32(len(rb.shstrtab))
	rb.shstrtab = append(rb.shstrtab, []byte(s)...)
	rb.shstrtab = append(rb.shstrtab, 0)
	rb.shstrtabMap[s] = offset
	return offset
}

// vaddrToOffset converts a virtual address to a file offset using PT_LOAD segments
func (rb *ElfRebuilder) vaddrToOffset(vaddr uint64) uint64 {
	for _, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD {
			if vaddr >= phdr.Vaddr && vaddr < phdr.Vaddr+phdr.Memsz {
				offset := phdr.Offset + (vaddr - phdr.Vaddr)
				return offset
			}
		}
	}
	// If not found in any PT_LOAD, return vaddr as-is (fallback)
	return vaddr
}

// addSection adds a new section to the rebuilder
func (rb *ElfRebuilder) addSection(name string, shType uint32, flags uint64, addr uint64, data []byte, link uint32, info uint32, addralign uint64, entsize uint64) int {
	nameOffset := rb.addShstrtabString(name)

	// Convert virtual address to file offset
	// For sections that exist in PT_LOAD segments, we use their original offset
	// For sections we create (like .shstrtab), offset will be set in calculateLayout
	fileOffset := rb.vaddrToOffset(addr)

	section := Elf64_Shdr{
		Name:      nameOffset,
		Type:      shType,
		Flags:     flags,
		Addr:      addr,
		Offset:    fileOffset,
		Size:      uint64(len(data)),
		Link:      link,
		Info:      info,
		Addralign: addralign,
		Entsize:   entsize,
	}

	idx := len(rb.sections)
	rb.sections = append(rb.sections, section)
	if len(data) > 0 {
		rb.sectionData[idx] = data
	}

	return idx
}

// addSectionHeader adds a section header for data already in PT_LOAD segments
// This does NOT store any data - the section just points to existing segment data
func (rb *ElfRebuilder) addSectionHeader(name string, shType uint32, flags uint64, addr uint64, size uint64, link uint32, info uint32, addralign uint64, entsize uint64) int {
	nameOffset := rb.addShstrtabString(name)

	// Convert virtual address to file offset
	fileOffset := rb.vaddrToOffset(addr)

	section := Elf64_Shdr{
		Name:      nameOffset,
		Type:      shType,
		Flags:     flags,
		Addr:      addr,
		Offset:    fileOffset,
		Size:      size,
		Link:      link,
		Info:      info,
		Addralign: addralign,
		Entsize:   entsize,
	}

	idx := len(rb.sections)
	rb.sections = append(rb.sections, section)
	// No data stored - section points to data in PT_LOAD segment

	return idx
}

// buildSections creates all necessary sections from the ElfReader data
func (rb *ElfRebuilder) buildSections() error {
	logInfo(cText("* Building ELF sections..."))

	// 1. NULL section (required)
	rb.nullSectionIdx = rb.addSection("", SHT_NULL, 0, 0, nil, 0, 0, 0, 0)

	// 2. .dynstr section (dynamic string table)
	if len(rb.reader.newStrtab) > 0 {
		rb.dynstrSectionIdx = rb.addSection(
			".dynstr",
			SHT_STRTAB,
			SHF_ALLOC,
			rb.reader.strtabOffset,
			rb.reader.newStrtab,
			0, 0, 1, 0,
		)
		logInfo(cText("   + .dynstr: "), fValue(len(rb.reader.newStrtab)), cText(" bytes"))
	}

	// 3. .dynsym section (dynamic symbol table)
	if len(rb.reader.newSymbols) > 0 {
		symData := makeBytes(rb.reader.newSymbols)

		// Count local symbols for Info field
		localCount := uint32(0)
		for _, sym := range rb.reader.newSymbols {
			if sym.stBind() == STB_LOCAL {
				localCount += 1
			}
		}

		rb.dynsymSectionIdx = rb.addSection(
			".dynsym",
			SHT_DYNSYM,
			SHF_ALLOC,
			rb.reader.symtabOffset,
			symData,
			uint32(rb.dynstrSectionIdx),
			localCount,
			8, 24,
		)
		logInfo(cText("   + .dynsym: "), fValue(len(rb.reader.newSymbols)), cText(" symbols"))
	}

	// 4. .hash section (if present)
	if rb.reader.hashOffset != 0 && rb.reader.hashSize > 0 {
		rb.hashSectionIdx = rb.addSectionHeader(
			".hash",
			SHT_HASH,
			SHF_ALLOC,
			rb.reader.hashOffset,
			rb.reader.hashSize,
			uint32(rb.dynsymSectionIdx),
			0, 8, 4,
		)
		logInfo(cText("   + .hash: "), fValue(rb.reader.hashSize), cText(" bytes"))
	}

	// 5. .gnu.hash section (if present)
	if rb.reader.gnuHashOffset != 0 && rb.reader.gnuHashSize > 0 {
		rb.gnuHashSectionIdx = rb.addSectionHeader(
			".gnu.hash",
			SHT_GNU_HASH,
			SHF_ALLOC,
			rb.reader.gnuHashOffset,
			rb.reader.gnuHashSize,
			uint32(rb.dynsymSectionIdx),
			0, 8, 0,
		)
		logInfo(cText("   + .gnu.hash: "), fValue(rb.reader.gnuHashSize), cText(" bytes"))
	}

	// 6. .rela.dyn section (RELA relocations)
	if len(rb.reader.Rela) > 0 {
		relaData := makeBytes(rb.reader.Rela)

		rb.relaSectionIdx = rb.addSection(
			".rela.dyn",
			SHT_RELA,
			SHF_ALLOC,
			rb.reader.relaOffset,
			relaData,
			uint32(rb.dynsymSectionIdx),
			0, 8, 24,
		)
		logInfo(cText("   + .rela.dyn: "), fValue(len(rb.reader.Rela)), cText(" entries"))
	}

	// 7. .rel.dyn section (REL relocations)
	if len(rb.reader.Rel) > 0 {
		relData := makeBytes(rb.reader.Rel)

		rb.relSectionIdx = rb.addSection(
			".rel.dyn",
			SHT_REL,
			SHF_ALLOC,
			rb.reader.relOffset,
			relData,
			uint32(rb.dynsymSectionIdx),
			0, 8, 16,
		)
		logInfo(cText("   + .rel.dyn: "), fValue(len(rb.reader.Rel)), cText(" entries"))
	}

	// 8. .rela.plt or .rel.plt section (PLT relocations)
	if len(rb.reader.JmpRela) > 0 {
		jmpRelaData := makeBytes(rb.reader.JmpRela)

		rb.pltRelSectionIdx = rb.addSection(
			".rela.plt",
			SHT_RELA,
			SHF_ALLOC|SHF_INFO_LINK,
			rb.reader.jmprelOffset,
			jmpRelaData,
			uint32(rb.dynsymSectionIdx),
			0, 8, 24,
		)
		logInfo(cText("   + .rela.plt: "), fValue(len(rb.reader.JmpRela)), cText(" entries"))
	} else if len(rb.reader.JmpRel) > 0 {
		jmpRelData := makeBytes(rb.reader.JmpRel)

		rb.pltRelSectionIdx = rb.addSection(
			".rel.plt",
			SHT_REL,
			SHF_ALLOC|SHF_INFO_LINK,
			rb.reader.jmprelOffset,
			jmpRelData,
			uint32(rb.dynsymSectionIdx),
			0, 8, 16,
		)
		logInfo(cText("   + .rel.plt: "), fValue(len(rb.reader.JmpRel)), cText(" entries"))
	}

	// 9. .dynamic section
	if rb.reader.dynamicOffset != 0 && rb.reader.dynamicSize > 0 {
		rb.dynamicSectionIdx = rb.addSectionHeader(
			".dynamic",
			SHT_DYNAMIC,
			SHF_ALLOC|SHF_WRITE,
			rb.reader.dynamicOffset,
			rb.reader.dynamicSize,
			uint32(rb.dynstrSectionIdx),
			0, 8, 16,
		)
		logInfo(cText("   + .dynamic: "), fValue(rb.reader.dynamicSize/16), cText(" entries"))
	}

	// 10. .got section (Global Offset Table)
	if rb.reader.gotOffset != 0 && rb.reader.gotSize > 0 {
		rb.gotSectionIdx = rb.addSectionHeader(
			".got",
			SHT_PROGBITS,
			SHF_ALLOC|SHF_WRITE,
			rb.reader.gotOffset,
			rb.reader.gotSize,
			0, 0, 8, 8,
		)
		logInfo(cText("   + .got: "), fValue(rb.reader.gotSize), cText(" bytes"))
	}

	// 11. .init_array section
	if rb.reader.initArrayOffset != 0 && rb.reader.initArraySize > 0 {
		rb.initArraySectionIdx = rb.addSectionHeader(
			".init_array",
			SHT_INIT_ARRAY,
			SHF_ALLOC|SHF_WRITE,
			rb.reader.initArrayOffset,
			rb.reader.initArraySize,
			0, 0, 8, 8,
		)
		logInfo(cText("   + .init_array: "), fValue(rb.reader.initArraySize), cText(" bytes"))
	}

	// 12. .fini_array section
	if rb.reader.finiArrayOffset != 0 && rb.reader.finiArraySize > 0 {
		rb.finiArraySectionIdx = rb.addSectionHeader(
			".fini_array",
			SHT_FINI_ARRAY,
			SHF_ALLOC|SHF_WRITE,
			rb.reader.finiArrayOffset,
			rb.reader.finiArraySize,
			0, 0, 8, 8,
		)
		logInfo(cText("   + .fini_array: "), fValue(rb.reader.finiArraySize), cText(" bytes"))
	}

	// 13. .shstrtab section (section header string table) - must be last
	// We must add the name to the string table BEFORE calling addSection,
	// because addSection takes the data slice by value. If we don't do this,
	// the data slice passed to addSection won't contain the name of the section itself,
	// leading to a truncated .shstrtab and a corrupt ELF.
	rb.addShstrtabString(".shstrtab")
	rb.shstrtabSectionIdx = rb.addSection(
		".shstrtab",
		SHT_STRTAB,
		0,
		0,
		rb.shstrtab,
		0, 0, 1, 0,
	)

	logInfo(cSuccess("   -> Created "), fValue(len(rb.sections)), cText(" sections"))

	return nil
}

func makeBytes[T any](data []T) []byte {
	var l int
	if l = len(data); l == 0 {
		return []byte{}
	}
	buf := make([]byte, binary.Size(data[0])*l)
	binary.Encode(buf, binary.LittleEndian, data)
	return buf
}

// calculateLayout determines file offsets for all sections
func (rb *ElfRebuilder) calculateLayout() error {
	logInfo(cText("* Calculating section layout..."))

	// Find the end of all PT_LOAD segments to know where we can place sections
	maxSegmentEnd := uint64(0)
	for _, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD {
			segmentEnd := phdr.Offset + phdr.Filesz
			if segmentEnd > maxSegmentEnd {
				maxSegmentEnd = segmentEnd
			}
		}
	}

	// Start sections after all segment data
	rb.currentOffset = maxSegmentEnd

	// Align to 8 bytes
	rb.currentOffset = alignUp(rb.currentOffset, 8)

	logDebug(cText("   + Starting section layout at offset "), fAddress(rb.currentOffset))

	// Layout all sections
	// Most sections already have their offsets set from vaddrToOffset
	// We only need to set offsets for sections we're creating (like .shstrtab)
	for i := range rb.sections {
		if rb.sections[i].Type == SHT_NULL {
			continue
		}

		// Skip sections that already have offsets (they're in PT_LOAD segments)
		if rb.sections[i].Offset != 0 && rb.sections[i].Addr != 0 {
			logDebug(cText("   + Section "), fValue(i), cText(" already at offset "), fAddress(rb.sections[i].Offset))
			continue
		}

		// Align to section alignment requirement
		if rb.sections[i].Addralign > 0 {
			rb.currentOffset = alignUp(rb.currentOffset, rb.sections[i].Addralign)
		}

		rb.sections[i].Offset = rb.currentOffset
		rb.currentOffset += rb.sections[i].Size

		logDebug(cText("   + Section "), fValue(i), cText(" placed at offset "), fAddress(rb.sections[i].Offset),
			cText(", size "), fValue(rb.sections[i].Size))
	}

	// Align section header table
	rb.currentOffset = alignUp(rb.currentOffset, 8)

	// Find the maximum extent of all sections AND segments
	// We need to check both because:
	// - Sections point to data within segments
	// - But segments may extend beyond the last section
	// Start from maxSegmentEnd (calculated earlier) which is the end of all PT_LOAD data
	logDebug(cText("   + Finding max section extent, maxSegmentEnd was "), fAddress(maxSegmentEnd))
	maxExtent := maxSegmentEnd

	// Also check all sections in case any extend beyond segments (like .shstrtab)
	for i, section := range rb.sections {
		if section.Type != SHT_NULL {
			sectionEnd := section.Offset + section.Size
			logDebug(cText("     - Section "), fValue(i),
				cText(" offset="), fAddress(section.Offset),
				cText(" size="), fValue(section.Size),
				cText(" end="), fAddress(sectionEnd))
			if sectionEnd > maxExtent {
				logDebug(cText("       -> New max: "), fAddress(sectionEnd))
				maxExtent = sectionEnd
			}
		}
	}

	// Place section header table after everything
	rb.currentOffset = alignUp(maxExtent, 8)

	logInfo(cText("   -> Section header table at "), fAddress(rb.currentOffset))
	logInfo(cText("   -> Total file size: "), fValue(rb.currentOffset+uint64(len(rb.sections))*64), cText(" bytes"))

	return nil
}

// writeRelocations writes the rebuilt ELF file with all sections
func (rb *ElfRebuilder) writeRelocations(file *os.File) error {
	logInfo(cText("* Writing rebuilt ELF file..."))

	// Build sections
	if err := rb.buildSections(); err != nil {
		return fmt.Errorf("failed to build sections: %w", err)
	}

	// Calculate layout
	if err := rb.calculateLayout(); err != nil {
		return fmt.Errorf("failed to calculate layout: %w", err)
	}

	// Update ELF header
	newHeader := *rb.reader.ElfHeader
	logDebug(cText("   + Original e_shoff: "), fAddress(newHeader.ShdrOffset))
	logDebug(cText("   + rb.currentOffset: "), fAddress(rb.currentOffset))
	newHeader.ShdrOffset = rb.currentOffset
	newHeader.Shnum = uint16(len(rb.sections))
	newHeader.Shstrndx = uint16(rb.shstrtabSectionIdx)

	logDebug(cText("   + Setting e_shoff to "), fAddress(newHeader.ShdrOffset))
	logDebug(cText("   + Setting e_shnum to "), fValue(newHeader.Shnum))
	logDebug(cText("   + Setting e_shstrndx to "), fValue(newHeader.Shstrndx))

	// Write ELF header
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, newHeader); err != nil {
		return fmt.Errorf("failed to write ELF header: %w", err)
	}
	logInfo(cText("   + Wrote ELF header"))

	// Copy program headers from original file
	if _, err := file.Seek(int64(newHeader.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program headers: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, rb.reader.Phdrs); err != nil {
		return fmt.Errorf("failed to write program headers: %w", err)
	}
	logInfo(cText("   + Wrote program headers"))

	// Copy segment data from original file (the actual program code/data)
	// For memory dumps: data is at VADDR positions in the source file
	// We read from phdr.Vaddr (source) and write to phdr.Offset (output ELF)
	for i, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD && phdr.Filesz > 0 {
			// For memory dumps: read from Vaddr, write to Offset
			srcOffset := phdr.Vaddr  // Where data is in the memory dump
			dstOffset := phdr.Offset // Where it should be in the output ELF
			copySize := phdr.Filesz

			// Skip ELF header and program headers if this segment starts at 0
			headerAndPhdrSize := uint64(rb.reader.ElfHeader.Ehsize) +
				uint64(rb.reader.ElfHeader.Phnum)*uint64(rb.reader.ElfHeader.Phentsize)

			if phdr.Offset == 0 {
				// This segment starts at the beginning, skip the headers
				srcOffset += headerAndPhdrSize
				dstOffset = headerAndPhdrSize
				copySize = phdr.Filesz - headerAndPhdrSize
				logDebug(cText("   + Skipping ELF+program headers ("), fValue(headerAndPhdrSize),
					cText(" bytes) for segment "), fValue(i))
			}

			if copySize == 0 {
				continue
			}

			logDebug(cText("   + Copying PT_LOAD segment "), fValue(i),
				cText(" from vaddr "), fAddress(srcOffset),
				cText(" to offset "), fAddress(dstOffset),
				cText(" size "), fValue(copySize))

			// Read from original file (memory dump - data at vaddr positions)
			segmentData := make([]byte, copySize)
			if _, err := rb.reader.File.Seek(int64(srcOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to segment %d in source: %w", i, err)
			}
			if _, err := io.ReadFull(rb.reader.File, segmentData); err != nil {
				return fmt.Errorf("failed to read segment %d data: %w", i, err)
			}

			// Write to output file at proper ELF offset
			if _, err := file.Seek(int64(dstOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to segment %d in output: %w", i, err)
			}
			if _, err := file.Write(segmentData); err != nil {
				return fmt.Errorf("failed to write segment %d data: %w", i, err)
			}
		}
	}
	logInfo(cText("   + Copied all PT_LOAD segments"))

	// Write section data for sections we created (not in PT_LOAD segments)
	// This is mainly .shstrtab
	for i, section := range rb.sections {
		if section.Type == SHT_NULL || section.Size == 0 {
			continue
		}

		// Only write sections that have data and are NOT in PT_LOAD segments
		// (i.e., sections with Addr == 0, which means we created them)
		data, ok := rb.sectionData[i]
		if !ok || section.Addr != 0 {
			continue
		}

		if _, err := file.Seek(int64(section.Offset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to section %d: %w", i, err)
		}

		if _, err := file.Write(data); err != nil {
			return fmt.Errorf("failed to write section %d: %w", i, err)
		}

		logDebug(cText("   + Wrote created section "), fValue(i), cText(" at "), fAddress(section.Offset))
	}

	// Write section header table
	if _, err := file.Seek(int64(newHeader.ShdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to section headers: %w", err)
	}

	for _, section := range rb.sections {
		if err := binary.Write(file, binary.LittleEndian, &section); err != nil {
			return fmt.Errorf("failed to write section header: %w", err)
		}
	}
	logInfo(cText("   + Wrote section header table"))

	logInfo(cSuccess("✓ Successfully wrote rebuilt ELF file"))

	return nil
}
