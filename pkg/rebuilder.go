package sofixer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
)

// ElfRebuilder handles the reconstruction of a valid ELF file from Android memory dumps.
//
// MEMORY DUMP FORMAT:
// Android memory dumps (typically from RAM) have a specific structure:
// - Data is positioned at its runtime virtual addresses (VAs)
// - File offsets do NOT follow standard ELF layout
// - Program headers describe where segments should be mapped in memory
//
// RECONSTRUCTION PROCESS:
// 1. Read existing program headers and dynamic section from the dump
// 2. Create section headers for all identifiable sections (.text, .data, .dynamic, etc.)
// 3. Copy PT_LOAD segment data from VAs in dump to proper file offsets in output
// 4. Add newly created sections (.shstrtab, rebuilt .dynsym/.dynstr with fixed relocations)
// 5. Write section header table at the end of the file
//
// REVERSE ENGINEERING CONSIDERATIONS:
// - Sections are carefully identified to match expected Android shared library structure
// - Symbol tables are rebuilt with corrected addresses for disassembler compatibility
// - Relocations are processed to restore original intended values
// - Gap analysis finds .text sections for code analysis tools (Ghidra/IDA/Binary Ninja)
//
// ElfRebuilder handles the reconstruction of a valid ELF file
type ElfRebuilder struct {
	reader *ElfReader

	// Section data
	sections     []Elf64_Shdr
	sectionNames []string
	sectionData  map[int][]byte

	// Layout information
	currentOffset uint64

	// Section indices
	nullSectionIdx       int
	dynstrSectionIdx     int
	dynsymSectionIdx     int
	hashSectionIdx       int
	gnuHashSectionIdx    int
	dynamicSectionIdx    int
	relSectionIdx        int
	relaSectionIdx       int
	pltRelSectionIdx     int
	gotSectionIdx        int
	initArraySectionIdx  int
	finiArraySectionIdx  int
	ehFrameHdrSectionIdx int
	ehFrameSectionIdx    int
	noteSectionIdx       int
	pltSectionIdx        int
	textSectionIdx       int
	shstrtabSectionIdx   int

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
			logger.Debug("dyn:strtab_ref", "tag", dyn.Tag.Text(), "old_val", fmt.Sprintf("0x%x", dyn.Val))
			// Read string from original strtab using old offset
			oldStr := rb.reader.readString(uint32(dyn.Val))
			logger.Debug("dyn:read_str", "tag", dyn.Tag.Text(), "offset", dyn.Val, "str", oldStr)
			if oldStr != "" {
				// Find the new offset in rebuilt strtab
				if newOffset, ok := rb.reader.newStrtabMap[oldStr]; ok {
					newDyn.Val = uint64(newOffset)
					logger.Debug("dyn:updated", "tag", dyn.Tag.Text(), "str", oldStr, "old_offset", dyn.Val, "new_offset", newOffset)
				} else {
					logger.Warn("Dynamic string not found in new strtab", "tag", dyn.Tag.Text(), "str", oldStr, "strtabSize", len(rb.reader.newStrtabMap))
				}
			} else {
				logger.Warn("Failed to read string", "tag", dyn.Tag.Text(), "offset", dyn.Val)
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
				offset := phdr.Offset + (vaddr - phdr.Vaddr)
				return offset
			}
		}
	}
	// If not found in any PT_LOAD, return vaddr as-is (fallback)
	return vaddr
}

// addSection adds a new section to the rebuilder
// Sections with custom data are placed at the end of the file (Offset=0, Addr=0)
// to prevent oversized rebuilt sections from corrupting adjacent segment data.
func (rb *ElfRebuilder) addSection(name string, shType SHT_Type, flags uint64, addr uint64, data []byte, link uint32, info uint32, addralign uint64, entsize uint64) int {
	nameOffset := rb.addShstrtabString(name)

	// For sections with custom data, place them at the end of the file
	// This prevents rebuilt sections (which may be larger than original)
	// from overwriting adjacent sections in PT_LOAD segments.
	fileOffset := uint64(0)
	sectionAddr := uint64(0)
	if len(data) == 0 {
		// No custom data - use original address/offset
		fileOffset = rb.vaddrToOffset(addr)
		sectionAddr = addr
	}

	section := Elf64_Shdr{
		Name:      nameOffset,
		Type:      shType,
		Flags:     flags,
		Addr:      sectionAddr,
		Offset:    fileOffset,
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

// addSectionHeader adds a section header for data already in PT_LOAD segments
// This does NOT store any data - the section just points to existing segment data
func (rb *ElfRebuilder) addSectionHeader(name string, shType SHT_Type, flags uint64, addr uint64, size uint64, link uint32, info uint32, addralign uint64, entsize uint64) int {
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
	rb.sectionNames = append(rb.sectionNames, name)
	// No data stored - section points to data in PT_LOAD segment

	return idx
}

// buildSections creates all necessary sections from the ElfReader data
func (rb *ElfRebuilder) buildSections() error {
	logger.Info("build:sections")

	// 1. NULL section (required)
	rb.addNullSection()

	// 2. .dynstr section (added early so .dynamic can link to it)
	rb.addDynstrSection()

	// 3. Computed sections (fixed addresses from PT_LOAD segments)
	rb.addComputedSections()

	// 4. Dynamic symbol table (requires sections above to fix St_Shndx)
	rb.addSymbolSections()

	// 5. Relocation sections (links to .dynsym)
	rb.addRelocationSections()

	// 6. Section header string table
	rb.addShstrtabSection()

	logger.Info("build:done", "count", len(rb.sections))

	return nil
}

// addNullSection creates the required NULL section
func (rb *ElfRebuilder) addNullSection() {
	rb.nullSectionIdx = rb.addSection("", SHT_NULL, 0, 0, nil, 0, 0, 0, 0)
}

// addDynstrSection creates the .dynstr section
func (rb *ElfRebuilder) addDynstrSection() {
	if len(rb.reader.newStrtab) > 0 {
		rb.dynstrSectionIdx = rb.addSection(
			".dynstr",
			SHT_STRTAB,
			SHF_ALLOC,
			rb.reader.strtabOffset,
			rb.reader.newStrtab,
			0, 0, 1, 0,
		)
		logger.Info("section | .dynstr", "size", len(rb.reader.newStrtab))
	}
}

// addSymbolSections creates .dynsym, .hash, and .gnu.hash sections
func (rb *ElfRebuilder) addSymbolSections() {
	// Fix symbol section indices before creating .dynsym
	rb.fixSymbolSections()

	// .dynsym section (dynamic symbol table)
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
		logger.Info("section | .dynsym", "count", len(rb.reader.newSymbols))
	}

	// .hash section (if present)
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
		logger.Info("section | .hash", "size", rb.reader.hashSize)
	}

	// .gnu.hash section (if present)
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
		logger.Info("section | .gnu.hash", "size", rb.reader.gnuHashSize)
	}
}

// addRelocationSections creates .rela.dyn, .rel.dyn, and PLT relocation sections
func (rb *ElfRebuilder) addRelocationSections() {
	// .rela.dyn section (RELA relocations)
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
		logger.Info("section | .rela.dyn", "count", len(rb.reader.Rela))
	}

	// .rel.dyn section (REL relocations)
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
		logger.Info("section | .rel.dyn", "count", len(rb.reader.Rel))
	}

	// .rela.plt or .rel.plt section (PLT relocations)
	if len(rb.reader.JmpRela) > 0 {
		jmpRelaData := makeBytes(rb.reader.JmpRela)
		rb.pltRelSectionIdx = rb.addSection(
			".rela.plt",
			SHT_RELA,
			SHF_ALLOC|SHF_INFO_LINK,
			rb.reader.jmprelOffset,
			jmpRelaData,
			uint32(rb.dynsymSectionIdx),
			uint32(rb.pltSectionIdx),
			8, 24,
		)
		logger.Info("section | .rela.plt", "count", len(rb.reader.JmpRela))
	} else if len(rb.reader.JmpRel) > 0 {
		jmpRelData := makeBytes(rb.reader.JmpRel)
		rb.pltRelSectionIdx = rb.addSection(
			".rel.plt",
			SHT_REL,
			SHF_ALLOC|SHF_INFO_LINK,
			rb.reader.jmprelOffset,
			jmpRelData,
			uint32(rb.dynsymSectionIdx),
			uint32(rb.pltSectionIdx),
			8, 16,
		)
		logger.Info("section | .rel.plt", "count", len(rb.reader.JmpRel))
	}
}

// addComputedSections adds all header-only sections pre-calculated by the reader
func (rb *ElfRebuilder) addComputedSections() {
	for _, cs := range rb.reader.computedSections {
		link := cs.Link

		// Special handling for .dynamic section - rebuild it with corrected string offsets
		if cs.Name == ".dynamic" {
			link = uint32(rb.dynstrSectionIdx)
			// Rebuild the dynamic section with corrected offsets
			dynamicData := rb.rebuildDynamicSection()
			rb.dynamicSectionIdx = rb.addSection(
				cs.Name, cs.Type, cs.Flags, cs.Addr,
				dynamicData, link, cs.Info, cs.Addralign, cs.Entsize,
			)
			logger.Info("section | .dynamic (rebuilt)", "addr", fmt.Sprintf("0x%x", cs.Addr), "size", len(dynamicData))
			continue
		}

		// Set link for .gnu.version to point to .dynsym
		if cs.Name == ".gnu.version" {
			link = uint32(rb.dynsymSectionIdx)
		}

		if cs.Name == ".dynamic" && link == 0 {
			link = uint32(rb.dynstrSectionIdx)
		}

		idx := rb.addSectionHeader(
			cs.Name,
			cs.Type,
			cs.Flags,
			cs.Addr,
			cs.Size,
			link,
			cs.Info,
			cs.Addralign,
			cs.Entsize,
		)

		// Map indices back for potential linkage
		if cs.Name == ".plt" {
			rb.pltSectionIdx = idx
		} else if cs.Name == ".got" {
			rb.gotSectionIdx = idx
		} else if cs.Name == ".init_array" {
			rb.initArraySectionIdx = idx
		} else if cs.Name == ".fini_array" {
			rb.finiArraySectionIdx = idx
		} else if cs.Name == ".eh_frame_hdr" {
			rb.ehFrameHdrSectionIdx = idx
		} else if cs.Name == ".eh_frame" {
			rb.ehFrameSectionIdx = idx
		} else if cs.Name == ".note.gnu.build-id" || (rb.noteSectionIdx == 0 && cs.Type == SHT_NOTE) {
			rb.noteSectionIdx = idx
		} else if cs.Name == ".text" {
			rb.textSectionIdx = idx
		}
		logger.Info("section", "name", cs.Name, "addr", fmt.Sprintf("0x%x", cs.Addr), "size", cs.Size)
	}
}

// addShstrtabSection creates the section header string table
func (rb *ElfRebuilder) addShstrtabSection() {
	rb.addShstrtabString(".shstrtab")
	rb.shstrtabSectionIdx = rb.addSection(
		".shstrtab",
		SHT_STRTAB,
		0,
		0,
		rb.shstrtab,
		0, 0, 1, 0,
	)
}

// fixSymbolSections updates St_Shndx for all new symbols based on their virtual address
func (rb *ElfRebuilder) fixSymbolSections() {
	for i := range rb.reader.newSymbols {
		sym := &rb.reader.newSymbols[i]
		if i == 0 {
			continue // Skip null symbol
		}

		shndx := rb.findSectionIndex(sym.St_Value)
		sym.St_Shndx = shndx

		if shndx != 0 {
			var name string
			for k, v := range rb.reader.newStrtabMap {
				if v == uint32(sym.St_Name) {
					name = k
					break
				}
			}
			logger.Debug("sym:shndx", "name", name, "value", fmt.Sprintf("0x%x", sym.St_Value), "ndx", shndx)
		}
	}
}

// findSectionIndex finds the section index for a given virtual address
func (rb *ElfRebuilder) findSectionIndex(addr uint64) uint16 {
	if addr == 0 {
		return 0 // SHN_UNDEF
	}

	bestIdx := 0
	minSize := uint64(0xffffffffffffffff)

	for i, sh := range rb.sections {
		if i == 0 || sh.Size == 0 || sh.Addr == 0 {
			continue // Skip NULL, empty, or non-memory sections
		}
		// Check if address is within section boundaries
		if addr >= sh.Addr && addr < sh.Addr+sh.Size {
			// Prefer the smallest section that contains the address (more specific)
			if sh.Size < minSize {
				minSize = sh.Size
				bestIdx = i
			}
		}
	}

	return uint16(bestIdx)
}

// getHeaderSize returns the total size of ELF header + program headers
func (rb *ElfRebuilder) getHeaderSize() uint64 {
	return uint64(rb.reader.ElfHeader.Ehsize) +
		uint64(rb.reader.ElfHeader.Phnum)*uint64(rb.reader.ElfHeader.Phentsize)
}

// calculateSegmentBounds returns the maximum file offset occupied by PT_LOAD segments.
// This is used to determine where new section data can be placed.
func (rb *ElfRebuilder) calculateSegmentBounds() uint64 {
	maxSegmentEnd := uint64(0)
	for _, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD {
			segmentEnd := phdr.Offset + phdr.Filesz
			if segmentEnd > maxSegmentEnd {
				maxSegmentEnd = segmentEnd
			}
		}
	}
	return maxSegmentEnd
}

// findMaxSectionExtent returns the maximum file offset used by any section.
// This includes both sections in PT_LOAD segments and newly created sections.
func (rb *ElfRebuilder) findMaxSectionExtent(maxSegmentEnd uint64) uint64 {
	maxExtent := maxSegmentEnd

	for i, section := range rb.sections {
		if section.Type != SHT_NULL {
			sectionEnd := section.Offset + section.Size
			logger.Debug("section:extent", "idx", i, "name", rb.sectionNames[i], "offset", fmt.Sprintf("0x%x", section.Offset), "size", section.Size, "end", fmt.Sprintf("0x%x", sectionEnd))
			if sectionEnd > maxExtent {
				logger.Debug("extent:max", "end", fmt.Sprintf("0x%x", sectionEnd))
				maxExtent = sectionEnd
			}
		}
	}

	return maxExtent
}

// assignNewSectionOffsets sets file offsets for sections that are not in PT_LOAD segments.
// These are newly created sections like .shstrtab that need space after the segment data.
func (rb *ElfRebuilder) assignNewSectionOffsets(startOffset uint64) {
	rb.currentOffset = startOffset

	for i := range rb.sections {
		if rb.sections[i].Type == SHT_NULL {
			continue
		}

		// Skip sections that already have offsets (they're in PT_LOAD segments)
		if rb.sections[i].Offset != 0 && rb.sections[i].Addr != 0 {
			continue
		}

		// Align to section alignment requirement
		if rb.sections[i].Addralign > 0 {
			rb.currentOffset = alignUp(rb.currentOffset, rb.sections[i].Addralign)
		}

		rb.sections[i].Offset = rb.currentOffset
		rb.currentOffset += rb.sections[i].Size
	}
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

// detectSectionOverlaps checks for overlapping sections and logs warnings
func (rb *ElfRebuilder) detectSectionOverlaps() {
	type sectionRange struct {
		idx   int
		name  string
		start uint64
		end   uint64
	}

	var ranges []sectionRange
	for i, sec := range rb.sections {
		if sec.Type == SHT_NULL || sec.Type == SHT_NOBITS || sec.Size == 0 {
			continue
		}
		ranges = append(ranges, sectionRange{
			idx:   i,
			name:  rb.sectionNames[i],
			start: sec.Offset,
			end:   sec.Offset + sec.Size,
		})
	}

	// Sort by start offset
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	// Check for overlaps
	for i := 0; i < len(ranges)-1; i++ {
		if ranges[i].end > ranges[i+1].start {
			logger.Warn("overlap:detected",
				"section1", ranges[i].name,
				"range1", fmt.Sprintf("0x%x-0x%x", ranges[i].start, ranges[i].end),
				"section2", ranges[i+1].name,
				"range2", fmt.Sprintf("0x%x-0x%x", ranges[i+1].start, ranges[i+1].end),
				"overlap", ranges[i].end-ranges[i+1].start,
			)
		}
	}
}

// calculateLayout determines file offsets for all sections.
// For memory dumps, most sections already have their offsets set from vaddrToOffset.
// This method assigns offsets to newly created sections (like .shstrtab) and
// determines the final position of the section header table.
func (rb *ElfRebuilder) calculateLayout() error {
	logger.Info("layout:calc")

	// Step 1: Detect and resolve overlaps for fixed-offset sections
	// If two sections overlap, we move the second one to the end of the file
	// (by setting its offset to 0 and letting Step 3 handle it).
	rb.resolveFixedOverlaps()

	// Step 2: Find where PT_LOAD segments end - this is where we can place new sections
	maxSegmentEnd := rb.calculateSegmentBounds()
	logger.Debug("segments:end", "offset", fmt.Sprintf("0x%x", maxSegmentEnd))

	// Step 3: Assign offsets to sections not already in PT_LOAD segments
	// Start after segment data, aligned to 8 bytes
	startOffset := alignUp(maxSegmentEnd, 8)
	rb.assignNewSectionOffsets(startOffset)

	// Step 4: Find the maximum extent including both segments and new sections
	maxExtent := rb.findMaxSectionExtent(maxSegmentEnd)

	// Step 5: Place section header table after everything, aligned to 8 bytes
	rb.currentOffset = alignUp(maxExtent, 8)

	logger.Info("shdr:offset", "offset", fmt.Sprintf("0x%x", rb.currentOffset))
	logger.Info("file:size", "bytes", rb.currentOffset+uint64(len(rb.sections))*64)

	// Step 6: Final check for section overlaps (warning only)
	rb.detectSectionOverlaps()

	return nil
}

// resolveFixedOverlaps finds sections with fixed offsets that overlap and "unsticks" them
func (rb *ElfRebuilder) resolveFixedOverlaps() {
	type sectionRange struct {
		idx   int
		start uint64
		end   uint64
	}

	var ranges []sectionRange
	for i, sec := range rb.sections {
		if sec.Type == SHT_NULL || sec.Type == SHT_NOBITS || sec.Size == 0 || sec.Offset == 0 {
			continue
		}
		ranges = append(ranges, sectionRange{
			idx:   i,
			start: sec.Offset,
			end:   sec.Offset + sec.Size,
		})
	}

	// Sort by start offset
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	for i := 0; i < len(ranges)-1; i++ {
		if ranges[i].end > ranges[i+1].start {
			idx1 := ranges[i].idx
			idx2 := ranges[i+1].idx

			// We have an overlap. Prefer to move sections that have custom/rebuilt data
			// (stored in sectionData) rather than sections that just point to segment data.
			// This prevents oversized rebuilt sections (like .dynstr) from corrupting
			// adjacent original sections (like .rela.dyn).
			_, hasData1 := rb.sectionData[idx1]
			_, hasData2 := rb.sectionData[idx2]

			idxToMove := idx2 // Default: move second section
			if hasData1 && !hasData2 {
				// First section has custom data, second doesn't - move first
				idxToMove = idx1
			}
			// If both or neither have data, move the second one (default)

			logger.Warn("overlap:resolve | moving to end",
				"section1", rb.sectionNames[idx1],
				"section2", rb.sectionNames[idx2],
				"moving", rb.sectionNames[idxToMove])

			// Set offset to 0 to mark it for relocation in assignNewSectionOffsets
			rb.sections[idxToMove].Offset = 0
			// Also clear addr so it's treated as a new section placement
			rb.sections[idxToMove].Addr = 0
		}
	}
}

// writeRelocations writes the rebuilt ELF file with all sections
func (rb *ElfRebuilder) writeRelocations(file *os.File) error {
	logger.Info("write:start")

	// Build sections
	if err := rb.buildSections(); err != nil {
		return fmt.Errorf("failed to build sections: %w", err)
	}

	// For memory dumps, we want to capture the full memory size of segments,
	// including the BSS (uninitialized data) which might contain runtime values.
	// So we expand Filesz to equal Memsz for all PT_LOAD segments.
	for i := range rb.reader.Phdrs {
		if rb.reader.Phdrs[i].Type == PT_LOAD {
			if rb.reader.Phdrs[i].Filesz < rb.reader.Phdrs[i].Memsz {
				logger.Info("segment:expand",
					"segment", i,
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
	logger.Debug("ehdr:old_shoff", "offset", fmt.Sprintf("0x%x", newHeader.ShdrOffset))
	logger.Debug("ehdr:new_shoff", "offset", fmt.Sprintf("0x%x", rb.currentOffset))
	newHeader.ShdrOffset = rb.currentOffset
	newHeader.Shnum = uint16(len(rb.sections))
	newHeader.Shstrndx = uint16(rb.shstrtabSectionIdx)

	logger.Debug("ehdr:shoff", "val", fmt.Sprintf("0x%x", newHeader.ShdrOffset))
	logger.Debug("ehdr:shnum", "val", newHeader.Shnum)
	logger.Debug("ehdr:shstrndx", "val", newHeader.Shstrndx)
	// Write ELF header

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, newHeader); err != nil {
		return fmt.Errorf("failed to write ELF header: %w", err)
	}
	logger.Info("write:ehdr")

	// Copy program headers from original file
	if _, err := file.Seek(int64(newHeader.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program headers: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, rb.reader.Phdrs); err != nil {
		return fmt.Errorf("failed to write program headers: %w", err)
	}
	logger.Info("write:phdr")

	var fileSize uint64 = 0
	if stat, err := rb.reader.File.Stat(); err == nil {
		fileSize = uint64(stat.Size())
	} else {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// Copy segment data from original file (the actual program code/data)
	// MEMORY DUMP FORMAT: For memory dumps captured from Android,
	// - Source file: data is at VADDR positions (phdr.Vaddr)
	// - Output ELF: data should be at standard file offsets (phdr.Offset)
	// We read from phdr.Vaddr in the dump and write to phdr.Offset in the rebuilt ELF.
	for i, phdr := range rb.reader.Phdrs {
		if phdr.Type == PT_LOAD && phdr.Filesz > 0 {
			srcOffset := phdr.Vaddr  // Where data is in the memory dump
			dstOffset := phdr.Offset // Where it should be in the output ELF
			copySize := phdr.Filesz

			// Skip ELF header and program headers if this segment starts at offset 0
			// (segments that map the file headers into memory at the load address)
			if phdr.Offset == 0 {
				headerAndPhdrSize := rb.getHeaderSize()
				srcOffset += headerAndPhdrSize
				dstOffset = headerAndPhdrSize
				copySize = phdr.Filesz - headerAndPhdrSize
				logger.Debug("segment:skip_headers", "headerSize", headerAndPhdrSize, "segment", i)
			}

			if copySize == 0 {
				continue
			}

			logger.Debug("segment:copy", "idx", i, "srcVaddr", fmt.Sprintf("0x%x", srcOffset), "dstOffset", fmt.Sprintf("0x%x", dstOffset), "size", copySize)

			// Verify source data is available
			if srcOffset+copySize > fileSize {
				copySize = uint64(max(int64(fileSize)-int64(srcOffset), 0))
				logger.Warn("Source data truncated", "adjustedSize", copySize)
			}

			// Read from memory dump
			segmentData := make([]byte, copySize)
			if _, err := rb.reader.File.Seek(int64(srcOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to source offset 0x%x for segment %d: %w", srcOffset, i, err)
			}
			if _, err := io.ReadFull(rb.reader.File, segmentData); err != nil {
				return fmt.Errorf("failed to read %d bytes for segment %d from source: %w", copySize, i, err)
			}

			// Write to output ELF at proper offset
			if _, err := file.Seek(int64(dstOffset), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to output offset 0x%x for segment %d: %w", dstOffset, i, err)
			}
			if _, err := file.Write(segmentData); err != nil {
				return fmt.Errorf("failed to write %d bytes for segment %d to output: %w", copySize, i, err)
			}
		}
	}
	logger.Info("write:segments")

	// Write section data for sections we created
	for i, section := range rb.sections {
		if section.Type == SHT_NULL || section.Size == 0 {
			continue
		}

		data, ok := rb.sectionData[i]
		if !ok {
			continue
		}

		if _, err := file.Seek(int64(section.Offset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to section %d (%s): %w", i, rb.sectionNames[i], err)
		}

		if n, err := file.Write(data); err != nil {
			return fmt.Errorf("failed to write section %d (%s): %w", i, rb.sectionNames[i], err)
		} else if uint64(n) != section.Size {
			logger.Warn("Short write for section", "name", rb.sectionNames[i], "expected", section.Size, "actual", n)
		}

		logger.Info("write:section", "idx", i, "name", rb.sectionNames[i], "offset", fmt.Sprintf("0x%x", section.Offset), "size", section.Size)
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
