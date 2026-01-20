package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/charmbracelet/log"
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
	r.copyInput()

	// Fix program headers - write normalized Vaddr values
	phdrOffset := r.ElfHeader.PhdrOffset
	for i, phdr := range r.Phdrs {
		offset := phdrOffset + uint64(i)*uint64(r.ElfHeader.Phentsize)
		// Write fixed Offset, Vaddr & Paddr at offset+8
		if err := r.writeAtOffset(offset+8, phdr.Vaddr); err != nil {
			return fmt.Errorf("failed to write phdr offset %d: %w", phdr.Vaddr, err)
		}
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
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("phdr:write", "idx", i, "type", phdr.Type.Text(), "vaddr", phdr.Vaddr, "paddr", phdr.Vaddr, "filesz", size, "memsz", size)
		}
	}
	logger.Info("phdr:write", "count", len(r.Phdrs))

	if err := r.writeFixedInitsFinis(); err != nil {
		return fmt.Errorf("failed to write init/fini arrays: %w", err)
	}

	// Build and write relocs
	if err := r.writeFixedRelocs(); err != nil {
		return fmt.Errorf("failed to write relocs: %w", err)
	}

	// Build and write section headers
	if err := r.writeSectionHeaders(); err != nil {
		return fmt.Errorf("failed to write section headers: %w", err)
	}

	return nil
}

func (r *ElfRebuilder) copyInput() error {
	// Copy entire source file to output
	_, err := r.File.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}
	// Copy entire source file
	if _, err := r.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek source: %w", err)
	}
	copied, err := io.Copy(r.OutFile, r.File)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	logger.Info("file:copy", "size", copied)
	return nil
}

func (r *ElfRebuilder) addSection(name string, shType SHT_Type, flags uint64, addr uint64, size uint64, link uint32, info uint32, entsize uint64) int {
	nameOffset := r.addSectionName(name)
	section := Elf64_Shdr{
		Name:      nameOffset,
		Type:      shType,
		Flags:     flags,
		Addr:      addr,
		Offset:    addr,
		Size:      size,
		Link:      link,
		Info:      info,
		Addralign: 8,
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
	// Track end of metadata to avoid overlap with .text
	var maxMetadataEnd uint64 = 0

	// Helper to track metadata end
	trackMetadata := func(addr, size uint64) {
		end := addr + size
		if end > maxMetadataEnd {
			maxMetadataEnd = end
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
	var pendingSections []sectionInfo

	// 1. .dynstr - dynamic string table
	if r.strtabOffset != 0 && r.strtabSize != 0 {
		pendingSections = append(pendingSections, sectionInfo{".dynstr", SHT_STRTAB, SHF_ALLOC,
			r.strtabOffset, r.strtabSize, 0, 0, 0})
		trackMetadata(r.strtabOffset, r.strtabSize)
	}

	// 2. .dynsym - dynamic symbol table
	if r.symtabOffset != 0 && r.symCount > 0 {
		symSize := r.symCount * uint64(binary.Size(Elf64_Sym{}))
		// sh_info = index of first non-local (GLOBAL/WEAK) symbol
		firstGlobalIdx := uint32(1) // Default: skip null symbol
		for i, sym := range r.Symbols {
			if sym.stBind() != STB_LOCAL {
				firstGlobalIdx = uint32(i)
				break
			}
		}
		pendingSections = append(pendingSections, sectionInfo{".dynsym", SHT_DYNSYM, SHF_ALLOC,
			r.symtabOffset, symSize, 0, firstGlobalIdx, 24})
		trackMetadata(r.symtabOffset, symSize)
	}

	// 3. .hash
	if r.hashOffset != 0 {
		pendingSections = append(pendingSections, sectionInfo{".hash", SHT_HASH, SHF_ALLOC,
			r.hashOffset, r.hashSize, 0, 0, 4})
		trackMetadata(r.hashOffset, r.hashSize)
	}

	// 4. .gnu.hash
	if r.gnuHashOffset != 0 {
		pendingSections = append(pendingSections, sectionInfo{".gnu.hash", SHT_GNU_HASH, SHF_ALLOC,
			r.gnuHashOffset, r.gnuHashSize, 0, 0, 8})
		trackMetadata(r.gnuHashOffset, r.gnuHashSize)
	}

	// 5. .gnu.version - version index array (2 bytes per symbol)
	if r.versymOffset != 0 && r.symCount > 0 {
		versymSize := r.symCount * 2 // uint16 per symbol
		pendingSections = append(pendingSections, sectionInfo{".gnu.version", SHT_GNU_VERSYM, SHF_ALLOC,
			r.versymOffset, versymSize, 0, 0, 2})
		trackMetadata(r.versymOffset, versymSize)
	}

	// 6. .gnu.version_r - version requirements
	if r.verneedOffset != 0 && r.verneedSize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".gnu.version_r", SHT_GNU_VERNEED, SHF_ALLOC,
			r.verneedOffset, r.verneedSize, 0, uint32(r.verneedNum), 4})
		trackMetadata(r.verneedOffset, r.verneedSize)
	}

	// 5. .rela.dyn or .rel.dyn
	if r.relOffset != 0 && r.relSize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".rel.dyn", SHT_REL, SHF_ALLOC,
			r.relOffset, r.relSize, 0, 0, 16})
		trackMetadata(r.relOffset, r.relSize)
	}
	if r.relaOffset != 0 && r.relaSize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".rela.dyn", SHT_RELA, SHF_ALLOC,
			r.relaOffset, r.relaSize, 0, 0, 24})
		trackMetadata(r.relaOffset, r.relaSize)
	}

	// 6. .rel.plt or .rela.plt
	if r.jmprelOffset != 0 && r.jmprelSize > 0 {
		switch r.jmprelEntrySize {
		case 16:
			pendingSections = append(pendingSections, sectionInfo{".rel.plt", SHT_REL, SHF_ALLOC|SHF_INFO_LINK,
				r.jmprelOffset, r.jmprelSize, 0, 0, 16})
		case 24:
			pendingSections = append(pendingSections, sectionInfo{".rela.plt", SHT_RELA, SHF_ALLOC|SHF_INFO_LINK,
				r.jmprelOffset, r.jmprelSize, 0, 0, 24})
		}
		trackMetadata(r.jmprelOffset, r.jmprelSize)
	}

	// 7a. .init
	if r.initOffset != 0 {
		pendingSections = append(pendingSections, sectionInfo{".init", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
			r.initOffset, 8, 0, 0, 4})
		trackMetadata(r.initOffset, 8)
	}
	// 7b. .fini
	if r.finiOffset != 0 {
		pendingSections = append(pendingSections, sectionInfo{".fini", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
			r.finiOffset, 8, 0, 0, 4})
		trackMetadata(r.finiOffset, 8)
	}

	// 8. .plt - Procedure Linkage Table
	// Calculated from .rela.plt entries
	if r.jmprelSize > 0 && r.jmprelEntrySize > 0 {
		count := r.jmprelSize / r.jmprelEntrySize
		pltSize := uint64(32) + count*16 // 32 byte header + 16 bytes per entry
		pltStart := AlignUp(maxMetadataEnd, 16)

		pendingSections = append(pendingSections, sectionInfo{".plt", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
			pltStart, pltSize, 0, 0, 16})
		trackMetadata(pltStart, pltSize)
	}

	// 9. .dynamic
	if r.dynamicAddr != 0 && r.dynamicSize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".dynamic", SHT_DYNAMIC, SHF_ALLOC|SHF_WRITE,
			r.dynamicOffset, r.dynamicSize, 0, 0, 16})
	}

	// 10. .got
	if r.gotOffset != 0 && r.gotSize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".got", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,
			r.gotOffset, r.gotSize, 0, 0, 8})
	}

	// 11. .got.plt (DT_PLTGOT)
	if r.pltGotOffset != 0 && r.pltGotSize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".got.plt", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,
			r.pltGotOffset, r.pltGotSize, 0, 0, 8})
	}

	// 12. .init_array
	if r.initArrayOffset != 0 && r.initArraySize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".init_array", SHT_INIT_ARRAY, SHF_ALLOC|SHF_WRITE,
			r.initArrayOffset, r.initArraySize, 0, 0, 8})
	}

	// 13. .fini_array
	if r.finiArrayOffset != 0 && r.finiArraySize > 0 {
		pendingSections = append(pendingSections, sectionInfo{".fini_array", SHT_FINI_ARRAY, SHF_ALLOC|SHF_WRITE,
			r.finiArrayOffset, r.finiArraySize, 0, 0, 8})
	}

	// 14. .text - find from PT_LOAD with R+X flags
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && (phdr.Flags&PF_X) != 0 && (phdr.Flags&PF_R) != 0 {
			addr := phdr.Vaddr
			size := phdr.Memsz

			// Adjust start to avoid overlapping with metadata/headers
			minStart := AlignUp(maxMetadataEnd, 4)
			if minStart > addr {
				diff := minStart - addr
				if diff < size {
					addr = minStart
					size -= diff
				} else {
					size = 0
				}
			}

			if size > 0 {
				pendingSections = append(pendingSections, sectionInfo{".text", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
					addr, size, 0, 0, 0})
			}
			break
		}
	}

	// 11. .data - find from PT_LOAD with R+W flags (non-executable)
	for _, phdr := range r.Phdrs {
		if phdr.Type == PT_LOAD && (phdr.Flags&PF_W) != 0 && (phdr.Flags&PF_X) == 0 {
			addr := phdr.Vaddr
			size := max(phdr.Filesz, phdr.Memsz)

			for _, s := range pendingSections {
				if s.addr == addr && s.size > 0 {
					addr += s.size
					if size > s.size {
						size -= s.size
					} else {
						size = 0
					}
				}
			}

			if size > 0 {
				pendingSections = append(pendingSections, sectionInfo{".data", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,
					addr, size, 0, 0, 0})
			}
		}
	}

	// Sort by address
	sort.Slice(pendingSections, func(i, j int) bool {
		return pendingSections[i].addr < pendingSections[j].addr
	})

	// Add sorted sections
	for _, s := range pendingSections {
		idx := r.addSection(s.name, s.shType, s.flags, s.addr, s.size, s.link, s.info, s.entsize)
		if s.name == ".dynstr" {
			dynstrIdx = idx
		} else if s.name == ".dynsym" {
			dynsymIdx = idx
		}
	}

	// Update link fields
	for i := 1; i < len(r.sections); i++ {
		sec := &r.sections[i]
		switch sec.Type {
		case SHT_DYNSYM, SHT_HASH, SHT_GNU_HASH, SHT_GNU_VERSYM, SHT_REL, SHT_RELA:
			sec.Link = uint32(dynsymIdx)
		case SHT_STRTAB, SHT_DYNAMIC, SHT_GNU_VERNEED:
			if r.readSectionName(sec.Name) != ".shstrtab" {
				sec.Link = uint32(dynstrIdx)
			}
		}
	}

	// 12. .shstrtab - add name, will set offset later
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
	ss.Addr = shstrtabOffset
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
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("shdr:write", "idx", i, "addr", section.Addr, "size", section.Size, "name", r.readSectionName(section.Name))
		}
	}

	// e_shoff at offset 40 (8 bytes)
	if err := r.writeAtOffset(40, shdrOffset); err != nil {
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

	// Fix symbol section indices
	fixedSyms := r.fixSymbolSectionIndices()
	if fixedSyms > 0 {
		if err := r.writeSymbolShndx(); err != nil {
			return fmt.Errorf("failed to fix symbol shndx: %w", err)
		}
		logger.Info("sym:write", "count", fixedSyms)
	}

	return nil
}

// fixSymbolSectionIndices determines correct section indices for symbols
func (r *ElfRebuilder) fixSymbolSectionIndices() int {
	fixed := 0
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
			fixed++
		}
	}
	return fixed
}

// findSectionForAddr finds the section index that contains the given address
func (r *ElfRebuilder) findSectionForAddr(addr uint64) uint16 {
	for i, sec := range r.sections {
		if sec.Type == SHT_NULL || sec.Addr == 0 {
			continue
		}
		if addr >= sec.Addr && addr < sec.Addr+sec.Size {
			return uint16(i)
		}
	}
	return 0 // SHN_UNDEF
}

// writeSymbolShndx writes the fixed st_shndx values to the symbol table
func (r *ElfRebuilder) writeSymbolShndx() error {
	symEntrySize := uint64(binary.Size(Elf64_Sym{}))
	shndxOffset := uint64(6) // offset of st_shndx within Elf64_Sym

	for i, sym := range r.Symbols {
		if sym.St_Value == 0 || sym.St_Shndx == 0 {
			continue
		}
		// Skip special section indices
		if sym.St_Shndx >= 0xff00 {
			continue
		}

		offset := r.symtabOffset + uint64(i)*symEntrySize + shndxOffset
		if err := r.writeAtOffset(offset, sym.St_Shndx); err != nil {
			return err
		}
	}
	return nil
}

// writeFixedInitsFinis writes addresses for init_array & finit_array
func (r *ElfRebuilder) writeFixedInitsFinis() error {
	if r.initOffset != 0 {
		value := r.readUint64At(r.initOffset)
		if value > r.BaseAddr {
			newVal := value - r.BaseAddr
			if err := r.writeAtOffset(r.initOffset, newVal); err != nil {
				return fmt.Errorf("failed to write init: %w", err)
			}
			logger.Debug("init:write", "offset", r.initOffset, "val", newVal)
		}
	}

	if r.finiOffset != 0 {
		value := r.readUint64At(r.finiOffset)
		if value > r.BaseAddr {
			newVal := value - r.BaseAddr
			if err := r.writeAtOffset(r.finiOffset, newVal); err != nil {
				return fmt.Errorf("failed to write fini: %w", err)
			}
			logger.Debug("fini:write", "offset", r.finiOffset, "val", newVal)
		}
	}

	if r.initArraySize > 0 && r.initArrayOffset != 0 {
		initArrayCount := r.initArraySize / 8
		for i := range initArrayCount {
			offset := r.initArrayOffset + uint64(i)*8
			value := r.readUint64At(offset)
			if value > r.BaseAddr {
				newVal := value - r.BaseAddr
				if err := r.writeAtOffset(offset, newVal); err != nil {
					return fmt.Errorf("failed to write init_array: %w", err)
				}
				logger.Debug("init_array:write", "idx", i, "offset", offset, "val", newVal)
			}
		}
		logger.Info("init_array:write", "count", initArrayCount)
	}

	if r.finiArraySize > 0 && r.finiArrayOffset != 0 {
		finiArrayCount := r.finiArraySize / 8
		for i := range finiArrayCount {
			offset := r.finiArrayOffset + uint64(i)*8
			value := r.readUint64At(offset)
			if value > r.BaseAddr {
				newVal := value - r.BaseAddr
				if err := r.writeAtOffset(offset, newVal); err != nil {
					return fmt.Errorf("failed to write fini_array: %w", err)
				}
				logger.Debug("fini_array:write", "idx", i, "offset", offset, "val", newVal)
			}
		}
		logger.Info("fini_array:write", "count", finiArrayCount)
	}

	return nil
}

// writeFixedRelocs writes REL, RELA & JMPREL(A)
func (r *ElfRebuilder) writeFixedRelocs() error {
	// Fix REL relocations - write to target locations
	relCount := 0
	for i, rel := range r.Rel {
		// Target location is rel.Offset (already normalized)
		targetOffset := rel.Offset
		fixedVal := r.computeRelValue(&rel)
		if err := r.writeAtOffset(targetOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rel: %w", err)
		}
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("rel:write", "idx", i, "offset", targetOffset, "val", fixedVal, "type", rel.Type().Text())
		}
		relCount++
	}

	// Fix RELA relocations - write to target locations
	relaCount := 0
	for i, rela := range r.Rela {
		// Target location is rela.Offset (already normalized)
		targetOffset := rela.Offset
		fixedVal := r.computeRelaValue(&rela)
		if err := r.writeAtOffset(targetOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write rela: %w", err)
		}
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("rela:write", "idx", i, "offset", targetOffset, "val", fixedVal, "type", rela.Type().Text())
		}
		relaCount++
	}

	// Fix JmpRel relocations - write to target locations
	jmprelCount := 0
	for i, rel := range r.JmpRel {
		targetOffset := rel.Offset
		fixedVal := r.computeRelValue(&rel)
		if err := r.writeAtOffset(targetOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprel: %w", err)
		}
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("jmprel:write", "idx", i, "offset", targetOffset, "val", fixedVal, "type", rel.Type().Text())
		}
		jmprelCount++
	}

	// Fix JmpRela relocations - write to target locations
	jmprelaCount := 0
	for i, rela := range r.JmpRela {
		targetOffset := rela.Offset
		fixedVal := r.computeRelaValue(&rela)
		if err := r.writeAtOffset(targetOffset, fixedVal); err != nil {
			return fmt.Errorf("failed to write jmprela: %w", err)
		}
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("jmprela:write", "idx", i, "offset", targetOffset, "val", fixedVal, "type", rela.Type().Text())
		}
		jmprelaCount++
	}

	logger.Info("relocs:write", "count", relCount+relaCount+jmprelCount+jmprelaCount)

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
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("rel:resolve", "sym", symName, "type", sym.stType().Text(), "bind", sym.stBind().Text())
		}
		S = sym.St_Value
	}

	fileOffset := rel.Offset

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
		if logger.GetLevel() == log.DebugLevel {
			logger.Debug("rela:resolve", "sym", symName, "type", sym.stType().Text(), "bind", sym.stBind().Text())
		}
		S = int64(sym.St_Value)
	}

	A := rela.Addend // Keep as int64
	// rela.Offset is already normalized (relative offset, not absolute address)
	fileOffset := rela.Offset

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

// writeUint64At writes a uint64 value at the specified offset
func (r *ElfRebuilder) writeAtOffset(offset uint64, value any) error {
	if _, err := r.OutFile.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	return binary.Write(r.OutFile, binary.LittleEndian, value)
}
