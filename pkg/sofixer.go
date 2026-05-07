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
	Logger *log.Logger
	styles *log.Styles
)

func init() {
	// Create custom styles for the logger - minimalist machine-like format
	styles = log.DefaultStyles()

	// Symbolic prefixes with strict color coding
	styles.Levels[log.DebugLevel] = lipgloss.NewStyle().
		SetString("[?]").
		Foreground(lipgloss.Color("#6c7086"))
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().
		SetString("[+]").
		Foreground(lipgloss.Color("#74c7ec"))
	styles.Levels[log.WarnLevel] = lipgloss.NewStyle().
		SetString("[!]").
		Foreground(lipgloss.Color("#f9e2af"))
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().
		SetString("[x]").
		Foreground(lipgloss.Color("#f38ba8"))

	// Style for keys and values
	styles.Key = lipgloss.NewStyle().Foreground(lipgloss.Color("#6c7086"))
	styles.Value = lipgloss.NewStyle().Foreground(lipgloss.Color("#b4befe"))

	// Address values get orange highlight
	for _, key := range []string{"vaddr", "paddr", "addr", "offset", "base", "from", "to", "end", "start", "handle", "mmap_addr", "mmap_region", "input_path", "output_path", "path"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#fab387")).Transform(func(s string) string {
			if num, err := strconv.ParseUint(s, 0, 64); err == nil {
				return fmt.Sprintf("0x%x", num)
			}
			return s
		})
	}
	// Numbers get magenta
	for _, key := range []string{"index", "size", "memory_size", "file_size", "count", "entry_count", "entries", "total_size", "expected_count", "actual_count", "decoded_count", "section_count", "symbol_count", "program_header_count"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#CBA6F7"))
	}
	// Type tags get blue bold
	for _, key := range []string{"type", "tag", "reloc", "bind", "flags", "level"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa")).Bold(true)
	}
	// File paths get yellow
	for _, key := range []string{"file", "path", "runpath", "input_path", "output_path"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#f9e2af"))
	}
	// Names get green
	for _, key := range []string{"name", "symbol", "sym", "lib", "library", "section", "section1", "section2", "package", "tag"} {
		styles.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1"))
	}

	logger = log.NewWithOptions(os.Stdout, log.Options{
		ReportTimestamp: false,
		ReportCaller:    false,
	})
	logger.SetStyles(styles)
	Logger = logger
}

// FixELFHeaders attempts to fix common issues with ELF headers.
// verbosity: 0=quiet (warn only), 1=info, 2=debug
func FixELFHeaders(filePath string, baseAddr uint64, outputPath string, verbosity int) (error, string) {
	switch verbosity {
	case 0:
		logger.SetLevel(log.WarnLevel)
	case 1:
		logger.SetLevel(log.InfoLevel)
	case 2:
		logger.SetLevel(log.DebugLevel)
	default:
		logger.SetLevel(log.InfoLevel)
	}
	logger.Info("elf fix", "path", filePath, "base", baseAddr)

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

	err = rebuilder.WriteFixedElf()
	rebuilder.OutFile.Close()
	if err != nil {
		logger.Error("elf fin", "error", err, "output_path", outputPath)
		return err, ""
	}

	// Post-fix verification on the closed output file
	if info, statErr := os.Stat(outputPath); statErr == nil {
		CheckFixedElf(outputPath, baseAddr, uint64(info.Size()))
	}

	logger.Info("elf fin", "output_path", outputPath)
	return nil, "elf fin output_path=" + outputPath
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
					logger.Warn("partial read", "name", name, "expected_count", count, "actual_count", len(result))
				}
				return result, nil
			}
			return nil, fmt.Errorf("failed to read %s element %d at 0x%x: %w", name, i, offset, err)
		}
		result = append(result, elem)
	}

	return result, nil

}
