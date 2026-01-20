package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

var (
	// Logger instance with custom styles
	logger *log.Logger
	styles *log.Styles
)

func init() {
	// Create custom styles for the logger - minimalist machine-like format
	styles = log.DefaultStyles()

	// Symbolic prefixes with strict color coding
	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().
		SetString("[?]").
		Foreground(lipgloss.Color("243")) // grey - trace/debug
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().
		SetString("[+]").
		Foreground(lipgloss.Color("86")) // cyan - success/info
	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().
		SetString("[!]").
		Foreground(lipgloss.Color("221")) // yellow - warning
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("[x]").
		Foreground(lipgloss.Color("#f38ba8")) // red - error

	// Style for keys and values
	styles.Key = lipgloss.NewStyle().Foreground(lipgloss.Color("#585b70"))
	styles.Value = lipgloss.NewStyle().Foreground(lipgloss.Color("#b4befe"))

	// Address values get orange highlight
	for _, key := range []string{"vaddr", "paddr", "addr", "offset", "base", "from", "to", "end", "final_va", "range1", "range2", "e_shoff", "start", "val"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#fab387")).Transform(func(s string) string {
			if num, err := strconv.ParseUint(s, 0, 64); err == nil {
				return fmt.Sprintf("0x%x", num)
			}
			return s
		})
	}
	// Numbers get magenta
	for _, key := range []string{"idx", "size", "memsz", "filesz", "count", "e_shnum", "e_shstrndx", "phentsize", "entries", "totalSize"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#CBA6F7"))
	}
	// Type tags get blue bold
	for _, key := range []string{"type", "tag", "reloc", "bind", "flags"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa")).Bold(true)
	}
	// File paths get yellow
	for _, key := range []string{"file", "path", "runpath", "outpath"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#f9e2af"))
	}
	// Names get green
	for _, key := range []string{"name", "sym", "lib", "section", "section1", "section2"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1"))
	}

	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: false,
		ReportCaller:    false,
	})
	logger.SetStyles(styles)
}

// FixELFHeaders attempts to fix common issues with ELF headers.
// verbosity: 0=quiet (warn only), 1=info, 2=debug, 3=trace (granular)
func FixELFHeaders(filePath string, baseAddr uint64, outputPath string, verbosity int) (error, string) {
	switch verbosity {
	case 0:
		logger.SetLevel(log.WarnLevel)
	case 1:
		logger.SetLevel(log.InfoLevel)
	case 2:
		logger.SetLevel(log.DebugLevel)
	default:
		logger.SetLevel(log.DebugLevel) // Use Debug for 3+ but logic in callers will filter
	}
	logger.Info("elf:fix", "file", filePath, "base", baseAddr)

	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err), ""
	}
	defer file.Close()

	var reader ElfReader = ElfReader{
		File:      file,
		ElfHeader: new(Elf64_Ehdr),
		BaseAddr:  baseAddr,
	}

	err = reader.Read()
	if err != nil {
		return err, ""
	}

	rebuilder, err := NewElfRebuilder(&reader, outputPath)
	if err != nil {
		return fmt.Errorf("failed to create rebuilder: %w", err), ""
	}
	defer rebuilder.OutFile.Close()

	err = rebuilder.WriteFixedElf()
	if err != nil {
		logger.Error("elf:fin", "err", err, "outpath", outputPath)
		return err, ""
	}
	logger.Info("elf:fin success", "outpath", outputPath)

	successMsg := styles.Message.Render("elf:fin", "outpath", outputPath)
	return nil, successMsg
}

// readArray reads up to 'count' elements of type T from file at the given offset.
// Returns the successfully read elements and the actual count. On EOF, returns partial results without error.
func readArray[T any](file *os.File, offset uint64, count uint64, name string) ([]T, error) {
	if count == 0 {
		return []T{}, nil
	}

	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to %s at 0x%x: %w", name, offset, err)
	}

	// Try to read the full array first (most efficient for common case)
	array := make([]T, count)
	if err := binary.Read(file, binary.LittleEndian, array); err == nil {
		return array, nil
	}

	// On error, fall back to reading element by element for partial results
	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to %s at 0x%x: %w", name, offset, err)
	}

	result := make([]T, 0, count)
	for i := range count {
		var elem T
		if err := binary.Read(file, binary.LittleEndian, &elem); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// Return what we have so far
				if len(result) > 0 {
					logger.Warn("partial read", "name", name, "expected", count, "got", len(result))
				}
				return result, nil
			}
			return nil, fmt.Errorf("failed to read %s element %d at 0x%x: %w", name, i, offset, err)
		}
		result = append(result, elem)
	}

	return result, nil

}
