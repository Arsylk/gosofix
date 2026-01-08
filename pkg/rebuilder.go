package sofixer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// ElfRebuilder handles the reconstruction of a valid ELF file from Android memory dumps.
//
// SIMPLIFIED APPROACH (Ghidra-optimized):
// - Only create essential sections that Ghidra needs
// - Use header-only sections for metadata (point to existing PT_LOAD data)
// - Rebuilt sections (.dynstr, .dynsym) placed at end of file to avoid overlaps
//
// SECTIONS CREATED:
// 1. NULL         - Required first section
// 2. .dynstr      - Rebuilt string table
// 3. .dynsym      - Rebuilt symbol table
// 4. .dynamic     - Header-only, points to PT_DYNAMIC
// 5. .text        - Header-only, covers entire RX segment
// 6. .data        - Header-only, covers entire RW segment
// 7. .rela.dyn    - Header-only, points to original relocs (if present)
// 8. .shstrtab    - New section names
type ElfRebuilder struct {
	reader *ElfReader

	// Section data
	sections     []Elf64_Shdr
	sectionNames []string
	sectionData  map[int][]byte

	// Layout information
	currentOffset uint64

	// Section indices (minimal set)
	dynstrSectionIdx   int
	dynsymSectionIdx   int
	dynamicSectionIdx  int
	textSectionIdx     int
	dataSectionIdx     int
	relaSectionIdx     int
	shstrtabSectionIdx int

	// Section header string table
	shstrtab    []byte
	shstrtabMap map[string]uint32
}

// NewElfRebuilder creates a new ELF rebuilder
func NewElfRebuilder(reader *ElfReader) *ElfRebuilder {
	return &ElfRebuilder{
		reader:       reader,
		sections:     make([]Elf64_Shdr, 0),
		sectionNames: make([]string, 0),
		sectionData:  make(map[int][]byte),
		shstrtabMap:  make(map[string]uint32),
		shstrtab:     []byte{0}, // Start with null byte
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

// rebuildDynamicSection creates a new dynamic section with corrected STRTAB offsets
func (rb *ElfRebuilder) rebuildDynamicSection() []byte {
	var newDyns []Elf64_Dyn

	for _, dyn := range rb.reader.Dyns {
		newDyn := dyn

		// For string-referencing tags, resolve the old string and get new offset
		switch dyn.Tag {
		case DT_NEEDED, DT_SONAME, DT_RUNPATH:
			oldStr := rb.reader.readString(uint32(dyn.Val))
			if oldStr != "" {
				if newOffset, ok := rb.reader.newStrtabMap[oldStr]; ok {
					newDyn.Val = uint64(newOffset)
				}
			}
		}

		newDyns = append(newDyns, newDyn)
	}

	return makeBytes(newDyns)
}

// vaddrToOffset converts a virtual address to a file offset using PT_LOAD segments
func (rb *ElfRebuilder) vaddrToOffset(vaddr uint64) uint64 {
	for _, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD {
			if vaddr >= phdr.Vaddr && vaddr < phdr.Vaddr+phdr.Memsz {
				return phdr.Offset + (vaddr - phdr.Vaddr)
			}
		}
	}
	return vaddr
}

// addSection adds a new section with custom data (placed at end of file)
func (rb *ElfRebuilder) addSection(name string, shType SHT_Type, flags uint64, data []byte, link uint32, info uint32, addralign uint64, entsize uint64) int {
	nameOffset := rb.addShstrtabString(name)

	section := Elf64_Shdr{
		Name:      nameOffset,
		Type:      shType,
		Flags:     flags,
		Addr:      0, // No virtual address for rebuilt sections
		Offset:    0, // Will be assigned later
		Size:      uint64(len(data)),
		Link:      link,
		Info:      info,
		Addralign: addralign,
		Entsize:   entsize,
	}

	idx := len(rb.sections)
	rb.sections = append(rb.sections, section)
	rb.sectionNames = append(rb.sectionNames, name)
	if len(data) > 0 {
		rb.sectionData[idx] = data
	}

	return idx
}

// addSectionHeader adds a section header pointing to existing PT_LOAD data
func (rb *ElfRebuilder) addSectionHeader(name string, shType SHT_Type, flags uint64, addr uint64, size uint64, link uint32, info uint32, addralign uint64, entsize uint64) int {
	nameOffset := rb.addShstrtabString(name)
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
	rb.sectionNames = append(rb.sectionNames, name)

	return idx
}

// buildSections creates all necessary sections
func (rb *ElfRebuilder) buildSections() error {
	logger.Info("build:sections")

	// 1. NULL section (required)
	rb.addSection("", SHT_NULL, 0, nil, 0, 0, 0, 0)

	// 2. .dynstr - rebuilt string table
	if len(rb.reader.newStrtab) > 0 {
		rb.dynstrSectionIdx = rb.addSection(
			".dynstr", SHT_STRTAB, SHF_ALLOC,
			rb.reader.newStrtab,
			0, 0, 1, 0,
		)
		logger.Info("section | .dynstr", "size", len(rb.reader.newStrtab))
	}

	// 3. .dynsym - rebuilt symbol table
	if len(rb.reader.newSymbols) > 0 {
		symData := makeBytes(rb.reader.newSymbols)
		localCount := uint32(0)
		for _, sym := range rb.reader.newSymbols {
			if sym.stBind() == STB_LOCAL {
				localCount++
			}
		}

		rb.dynsymSectionIdx = rb.addSection(
			".dynsym", SHT_DYNSYM, SHF_ALLOC,
			symData,
			uint32(rb.dynstrSectionIdx), localCount,
			8, 24,
		)
		logger.Info("section | .dynsym", "count", len(rb.reader.newSymbols))
	}

	// 4. .dynamic - rebuilt with corrected string table offsets
	if rb.reader.dynamicOffset != 0 && len(rb.reader.Dyns) > 0 {
		dynData := rb.rebuildDynamicSection()
		rb.dynamicSectionIdx = rb.addSection(
			".dynamic", SHT_DYNAMIC, SHF_ALLOC|SHF_WRITE,
			dynData,
			uint32(rb.dynstrSectionIdx), 0,
			8, 16,
		)
		logger.Info("section | .dynamic", "entries", len(rb.reader.Dyns), "size", len(dynData))
	}

	// 5. .text - entire executable segment
	for _, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD && (phdr.Flags&PF_X) != 0 && (phdr.Flags&PF_R) != 0 {
			// Skip ELF headers if segment starts at 0
			addr := phdr.Vaddr
			size := phdr.Memsz
			if addr == 0 {
				headerSize := uint64(rb.reader.ElfHeader.Ehsize) + uint64(rb.reader.ElfHeader.Phnum)*uint64(rb.reader.ElfHeader.Phentsize)
				headerSize = alignUp(headerSize, 16)
				addr += headerSize
				size -= headerSize
			}

			rb.textSectionIdx = rb.addSectionHeader(
				".text", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
				addr, size,
				0, 0, 16, 0,
			)
			logger.Info("section | .text", "addr", fmt.Sprintf("0x%x", addr), "size", size)
			break // Only first executable segment
		}
	}

	// 6. .data - entire writable segment
	for _, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD && (phdr.Flags&PF_W) != 0 && (phdr.Flags&PF_X) == 0 {
			addr := phdr.Vaddr
			size := phdr.Memsz // Use Memsz to include BSS

			rb.dataSectionIdx = rb.addSectionHeader(
				".data", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,
				addr, size,
				0, 0, 16, 0,
			)
			logger.Info("section | .data", "addr", fmt.Sprintf("0x%x", addr), "size", size)
			break // Only first writable segment
		}
	}

	// 7. .rela.dyn - header-only (if present)
	if rb.reader.relaOffset != 0 && rb.reader.relaSize > 0 {
		rb.relaSectionIdx = rb.addSectionHeader(
			".rela.dyn", SHT_RELA, SHF_ALLOC,
			rb.reader.relaOffset, rb.reader.relaSize,
			uint32(rb.dynsymSectionIdx), 0,
			8, 24,
		)
		logger.Info("section | .rela.dyn", "addr", fmt.Sprintf("0x%x", rb.reader.relaOffset))
	} else if rb.reader.relOffset != 0 && rb.reader.relSize > 0 {
		rb.relaSectionIdx = rb.addSectionHeader(
			".rel.dyn", SHT_REL, SHF_ALLOC,
			rb.reader.relOffset, rb.reader.relSize,
			uint32(rb.dynsymSectionIdx), 0,
			8, 16,
		)
		logger.Info("section | .rel.dyn", "addr", fmt.Sprintf("0x%x", rb.reader.relOffset))
	}

	// 8. .init_array - constructor pointers (if present)
	if rb.reader.initArrayOffset != 0 && rb.reader.initArraySize > 0 {
		rb.addSectionHeader(
			".init_array", SHT_INIT_ARRAY, SHF_ALLOC|SHF_WRITE,
			rb.reader.initArrayOffset, rb.reader.initArraySize,
			0, 0, 8, 8,
		)
		logger.Info("section | .init_array", "addr", fmt.Sprintf("0x%x", rb.reader.initArrayOffset), "size", rb.reader.initArraySize)
	}

	// 9. .fini_array - destructor pointers (if present)
	if rb.reader.finiArrayOffset != 0 && rb.reader.finiArraySize > 0 {
		rb.addSectionHeader(
			".fini_array", SHT_FINI_ARRAY, SHF_ALLOC|SHF_WRITE,
			rb.reader.finiArrayOffset, rb.reader.finiArraySize,
			0, 0, 8, 8,
		)
		logger.Info("section | .fini_array", "addr", fmt.Sprintf("0x%x", rb.reader.finiArrayOffset), "size", rb.reader.finiArraySize)
	}

	// 10. .shstrtab - section names
	rb.addShstrtabString(".shstrtab")
	rb.shstrtabSectionIdx = rb.addSection(
		".shstrtab", SHT_STRTAB, 0,
		rb.shstrtab,
		0, 0, 1, 0,
	)

	logger.Info("build:done", "count", len(rb.sections))
	return nil
}

// calculateLayout determines file offsets for all sections
func (rb *ElfRebuilder) calculateLayout() error {
	logger.Info("layout:calc")

	// Find where PT_LOAD segments end
	maxSegmentEnd := uint64(0)
	for _, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD {
			segmentEnd := phdr.Offset + phdr.Filesz
			if segmentEnd > maxSegmentEnd {
				maxSegmentEnd = segmentEnd
			}
		}
	}

	// Place rebuilt sections after segment data, aligned to 8 bytes
	rb.currentOffset = alignUp(maxSegmentEnd, 8)

	for i := range rb.sections {
		if rb.sections[i].Type == SHT_NULL {
			continue
		}

		// Skip sections that already have offsets (header-only sections)
		if rb.sections[i].Offset != 0 {
			continue
		}

		// Align and assign offset
		if rb.sections[i].Addralign > 0 {
			rb.currentOffset = alignUp(rb.currentOffset, rb.sections[i].Addralign)
		}

		rb.sections[i].Offset = rb.currentOffset
		rb.currentOffset += rb.sections[i].Size
	}

	// Section header table goes at the very end
	rb.currentOffset = alignUp(rb.currentOffset, 8)
	logger.Info("shdr:offset", "offset", fmt.Sprintf("0x%x", rb.currentOffset))

	return nil
}

func makeBytes[T any](data []T) []byte {
	if len(data) == 0 {
		return []byte{}
	}
	var buf bytes.Buffer
	for _, item := range data {
		if err := binary.Write(&buf, binary.LittleEndian, item); err != nil {
			logger.Error("Failed to encode item", "err", err)
			return []byte{}
		}
	}
	return buf.Bytes()
}

// writeRelocations writes the rebuilt ELF file
func (rb *ElfRebuilder) writeRelocations(file *os.File) error {
	logger.Info("write:start")

	// Build sections
	if err := rb.buildSections(); err != nil {
		return fmt.Errorf("failed to build sections: %w", err)
	}

	// Expand PT_LOAD segments to include BSS for memory dumps
	for i := range rb.reader.Phdrs {
		if rb.reader.Phdrs[i].Type == PT_LOAD {
			if rb.reader.Phdrs[i].Filesz < rb.reader.Phdrs[i].Memsz {
				logger.Info("segment:expand", "segment", i,
					"old_filesz", rb.reader.Phdrs[i].Filesz,
					"new_filesz", rb.reader.Phdrs[i].Memsz)
				rb.reader.Phdrs[i].Filesz = rb.reader.Phdrs[i].Memsz
			}
		}
	}

	// Calculate layout
	if err := rb.calculateLayout(); err != nil {
		return fmt.Errorf("failed to calculate layout: %w", err)
	}

	// Update ELF header
	newHeader := *rb.reader.ElfHeader
	newHeader.ShdrOffset = rb.currentOffset
	newHeader.Shnum = uint16(len(rb.sections))
	newHeader.Shstrndx = uint16(rb.shstrtabSectionIdx)

	// Write ELF header
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, newHeader); err != nil {
		return fmt.Errorf("failed to write ELF header: %w", err)
	}
	logger.Info("write:ehdr")

	// Write program headers
	if _, err := file.Seek(int64(newHeader.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program headers: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, rb.reader.Phdrs); err != nil {
		return fmt.Errorf("failed to write program headers: %w", err)
	}
	logger.Info("write:phdr")

	// Get source file size
	var fileSize uint64
	if stat, err := rb.reader.File.Stat(); err == nil {
		fileSize = uint64(stat.Size())
	} else {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// Copy PT_LOAD segment data from memory dump
	for i, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD && phdr.Filesz > 0 {
			srcOffset := phdr.Vaddr
			dstOffset := phdr.Offset
			copySize := phdr.Filesz

			// Skip headers if segment starts at 0
			if phdr.Offset == 0 {
				headerSize := uint64(rb.reader.ElfHeader.Ehsize) + uint64(rb.reader.ElfHeader.Phnum)*uint64(rb.reader.ElfHeader.Phentsize)
				srcOffset += headerSize
				dstOffset = headerSize
				copySize = phdr.Filesz - headerSize
			}

			if copySize == 0 {
				continue
			}

			// Truncate if source is too small
			if srcOffset+copySize > fileSize {
				copySize = uint64(max(int64(fileSize)-int64(srcOffset), 0))
			}

			// Read from memory dump
			segmentData := make([]byte, copySize)
			if _, err := rb.reader.File.Seek(int64(srcOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek for segment %d: %w", i, err)
			}
			if _, err := io.ReadFull(rb.reader.File, segmentData); err != nil {
				return fmt.Errorf("failed to read segment %d: %w", i, err)
			}

			// Write to output
			if _, err := file.Seek(int64(dstOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek for output segment %d: %w", i, err)
			}
			if _, err := file.Write(segmentData); err != nil {
				return fmt.Errorf("failed to write segment %d: %w", i, err)
			}
		}
	}
	logger.Info("write:segments")

	// Write rebuilt section data
	for i, section := range rb.sections {
		if section.Type == SHT_NULL || section.Size == 0 {
			continue
		}

		data, ok := rb.sectionData[i]
		if !ok {
			continue
		}

		if _, err := file.Seek(int64(section.Offset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to section %s: %w", rb.sectionNames[i], err)
		}
		if _, err := file.Write(data); err != nil {
			return fmt.Errorf("failed to write section %s: %w", rb.sectionNames[i], err)
		}

		logger.Info("write:section", "name", rb.sectionNames[i], "offset", fmt.Sprintf("0x%x", section.Offset))
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
	logger.Info("write:shdr")

	logger.Info("done", "path", file.Name())
	return nil
}
