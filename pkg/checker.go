package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/log"
	"github.com/ianlancetaylor/demangle"
)

// elfMetadata holds parsed ELF structures for granular address resolution.
type elfMetadata struct {
	ehdr     Elf64_Ehdr
	phdrs    []Elf64_Phdr
	shdrs    []Elf64_Shdr
	shstrtab []byte
	symbols  []resolvedSymbol
}

type resolvedSymbol struct {
	name  string
	value uint64
	size  uint64
	info  uint8
}

// CheckFixedElf opens the output ELF and runs post-fix sanity checks.
// Logs diagnostics using the supplied logger. Returns issues found.
func CheckFixedElf(lg *log.Logger, path string, baseAddr uint64, totalSize uint64) []string {
	file, err := os.Open(path)
	if err != nil {
		lg.Error("check:open", "path", path, "err", err)
		return []string{fmt.Sprintf("failed to open: %v", err)}
	}
	defer file.Close()

	var issues []string

	// 1. ELF header sanity
	meta, ehdrIssues := readElfMetadata(lg, file)
	issues = append(issues, ehdrIssues...)
	if len(ehdrIssues) > 0 && meta == nil {
		return issues // Can't proceed without basic headers
	}

	// 2. Program header consistency
	phdrIssues := checkProgramHeadersConsistency(meta.phdrs)
	issues = append(issues, phdrIssues...)

	// 3. Residual absolute addresses in data segments
	if baseAddr != 0 {
		residuals := scanResidualAddresses(lg, file, meta, baseAddr, totalSize)
		issues = append(issues, residuals...)
	}

	if len(issues) == 0 {
		lg.Info("check:pass", "path", path)
	} else {
		lg.Warn("check:issues", "path", path, "count", len(issues))
	}

	return issues
}

// readElfMetadata reads Ehdr, Phdrs, Shdrs, and Symbols for resolution.
func readElfMetadata(lg *log.Logger, file *os.File) (*elfMetadata, []string) {
	var issues []string
	meta := &elfMetadata{}

	// Ehdr
	if err := binary.Read(file, binary.LittleEndian, &meta.ehdr); err != nil {
		return nil, []string{fmt.Sprintf("ehdr:read failed: %v", err)}
	}

	// Basic validation
	if meta.ehdr.Magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		issues = append(issues, "ehdr:bad_magic")
	}
	if meta.ehdr.Class != 2 {
		issues = append(issues, "ehdr:bad_class")
	}

	// Phdrs
	if meta.ehdr.Phnum > 0 {
		meta.phdrs = make([]Elf64_Phdr, meta.ehdr.Phnum)
		if _, err := file.Seek(int64(meta.ehdr.PhdrOffset), io.SeekStart); err != nil {
			issues = append(issues, fmt.Sprintf("phdr:seek failed: %v", err))
			return meta, issues
		}
		if err := binary.Read(file, binary.LittleEndian, meta.phdrs); err != nil {
			issues = append(issues, fmt.Sprintf("phdr:read failed: %v", err))
			return meta, issues
		}
	}

	// Shdrs
	if meta.ehdr.Shnum > 0 {
		meta.shdrs = make([]Elf64_Shdr, meta.ehdr.Shnum)
		if _, err := file.Seek(int64(meta.ehdr.ShdrOffset), io.SeekStart); err != nil {
			issues = append(issues, fmt.Sprintf("shdr:seek failed: %v", err))
			return meta, issues
		}
		if err := binary.Read(file, binary.LittleEndian, meta.shdrs); err != nil {
			issues = append(issues, fmt.Sprintf("shdr:read failed: %v", err))
			return meta, issues
		}

		// Shstrtab
		if meta.ehdr.Shstrndx != 0 && meta.ehdr.Shstrndx < meta.ehdr.Shnum {
			shstr := meta.shdrs[meta.ehdr.Shstrndx]
			meta.shstrtab = make([]byte, shstr.Size)
			n, err := file.ReadAt(meta.shstrtab, int64(shstr.Offset))
			if err != nil || n != int(shstr.Size) {
				issues = append(issues, fmt.Sprintf("shstrtab:read failed: read=%d size=%d err=%v", n, shstr.Size, err))
			}
		}

		// Read Symbol Tables
		for _, sh := range meta.shdrs {
			if sh.Type == SHT_DYNSYM || sh.Type == SHT_SYMTAB {
				r, symIssues := meta.readSymbols(file, sh)
				issues = append(issues, symIssues...)
				meta.symbols = append(meta.symbols, r...)
			}
		}
	}

	if len(issues) == 0 {
		lg.Info("check:metadata", "phdrs", len(meta.phdrs), "shdrs", len(meta.shdrs), "symbols", len(meta.symbols))
	}

	return meta, issues
}

func (m *elfMetadata) readSymbols(file *os.File, sh Elf64_Shdr) ([]resolvedSymbol, []string) {
	var issues []string
	if sh.Entsize == 0 {
		return nil, nil
	}
	count := sh.Size / sh.Entsize
	rawSyms := make([]Elf64_Sym, count)
	if _, err := file.Seek(int64(sh.Offset), io.SeekStart); err != nil {
		issues = append(issues, fmt.Sprintf("symbols:seek failed at 0x%x: %v", sh.Offset, err))
		return nil, issues
	}
	if err := binary.Read(file, binary.LittleEndian, rawSyms); err != nil {
		issues = append(issues, fmt.Sprintf("symbols:read failed at 0x%x: %v", sh.Offset, err))
		return nil, issues
	}

	var strtab []byte
	if sh.Link != 0 && uint16(sh.Link) < m.ehdr.Shnum {
		strsh := m.shdrs[sh.Link]
		strtab = make([]byte, strsh.Size)
		n, err := file.ReadAt(strtab, int64(strsh.Offset))
		if err != nil || n != int(strsh.Size) {
			issues = append(issues, fmt.Sprintf("strtab:read failed at 0x%x: read=%d size=%d err=%v", strsh.Offset, n, strsh.Size, err))
		}
	}

	res := make([]resolvedSymbol, 0, count)
	for _, s := range rawSyms {
		if s.St_Name == 0 && s.St_Value == 0 {
			continue
		}
		name := readString(strtab, s.St_Name)
		// Demangle if it looks like a mangled name
		if demangled, err := demangle.ToString(name); err == nil {
			name = demangled
		}
		res = append(res, resolvedSymbol{
			name:  name,
			value: s.St_Value,
			size:  s.St_Size,
			info:  s.St_Info,
		})
	}
	return res, issues
}

func checkProgramHeadersConsistency(phdrs []Elf64_Phdr) []string {
	var issues []string
	var loadCount int
	for i, p := range phdrs {
		if p.Type != PT_LOAD {
			continue
		}
		loadCount++
		if p.Filesz != p.Memsz {
			issues = append(issues, fmt.Sprintf("phdr[%d]:filesz!=memsz filesz=0x%x memsz=0x%x", i, p.Filesz, p.Memsz))
		}
	}
	return issues
}

// readString returns the null-terminated string starting at `offset` in `data`,
// or "" if the offset is out of range.
func readString(data []byte, offset uint32) string {
	if offset >= uint32(len(data)) {
		return ""
	}
	end := offset
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

// scanResidualAddresses scans writable PT_LOAD segments for pointer-aligned
// values that fall within [baseAddr, baseAddr+totalSize]. For each hit,
// checks if (val - baseAddr) resolves to a legitimate offset within any
// PT_LOAD segment, which strongly indicates a missed normalization.
func scanResidualAddresses(lg *log.Logger, file *os.File, meta *elfMetadata, baseAddr uint64, totalSize uint64) []string {
	var issues []string
	upperBound := baseAddr + totalSize
	var totalScanned, totalResiduals, totalLegitimate int

	for _, p := range meta.phdrs {
		if p.Type != PT_LOAD || (p.Flags&PF_W) == 0 {
			continue
		}

		data := make([]byte, p.Filesz)
		n, err := file.ReadAt(data, int64(p.Offset))
		if err != nil && n == 0 {
			continue
		}
		data = data[:n]

		for off := 0; off+8 <= len(data); off += 8 {
			val := binary.LittleEndian.Uint64(data[off : off+8])
			if val < baseAddr || val >= upperBound {
				continue
			}

			totalResiduals++
			rebased := val - baseAddr
			vaddr := p.Vaddr + uint64(off)

			// Check if the rebased value points into any PT_LOAD segment
			target := resolveAddress(meta, rebased)
			if target == "" {
				continue
			}

			totalLegitimate++
			if totalLegitimate <= 5 {
				lg.Warn("check:residual",
					"vaddr", fmt.Sprintf("0x%x", vaddr),
					"val", fmt.Sprintf("0x%x", val),
					"rebased", fmt.Sprintf("0x%x", rebased),
					"target", target,
				)
			}
		}
		totalScanned += len(data) / 8
	}

	if totalLegitimate > 0 {
		issues = append(issues, fmt.Sprintf(
			"residual_addrs: %d values look like un-normalized pointers (%d total candidates, %d pointers scanned)",
			totalLegitimate, totalResiduals, totalScanned,
		))
		lg.Warn("check:residuals", "legitimate", totalLegitimate, "candidates", totalResiduals, "scanned", totalScanned)
	} else {
		lg.Info("check:residuals", "legitimate", 0, "candidates", totalResiduals, "scanned", totalScanned)
	}

	return issues
}

// resolveAddress checks what a rebased vaddr points to.
// Priority: Symbols > Sections > Segments.
func resolveAddress(meta *elfMetadata, vaddr uint64) string {
	// 1. Symbols (Best)
	for _, sym := range meta.symbols {
		if sym.value == 0 {
			continue
		}
		if vaddr == sym.value {
			return fmt.Sprintf("sym.%s", sym.name)
		}
		if vaddr > sym.value && vaddr < sym.value+sym.size {
			return fmt.Sprintf("sym.%s+0x%x", sym.name, vaddr-sym.value)
		}
	}

	// 2. Sections
	for i, sh := range meta.shdrs {
		if sh.Addr == 0 || sh.Size == 0 {
			continue
		}
		if vaddr >= sh.Addr && vaddr < sh.Addr+sh.Size {
			name := "unnamed"
			if m := meta.shstrtab; m != nil {
				name = readString(m, sh.Name)
			}
			return fmt.Sprintf("section[%d].%s+0x%x", i, name, vaddr-sh.Addr)
		}
	}

	// 3. Segments (Fallback)
	for _, p := range meta.phdrs {
		if p.Type != PT_LOAD {
			continue
		}
		if vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Memsz {
			perms := ""
			if p.Flags&PF_R != 0 {
				perms += "R"
			}
			if p.Flags&PF_W != 0 {
				perms += "W"
			}
			if p.Flags&PF_X != 0 {
				perms += "X"
			}
			return fmt.Sprintf("%s@0x%x+0x%x", perms, p.Vaddr, vaddr-p.Vaddr)
		}
	}
	return ""
}
