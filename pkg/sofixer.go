package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

// styles is built once and shared across all loggers. log.Styles values are
// immutable for our purposes (we only ever read from them), so this is safe to
// share between concurrent FixELFHeaders calls.
var styles = sync.OnceValue(buildStyles)

func buildStyles() *log.Styles {
	s := log.DefaultStyles()
	s.Levels[log.DebugLevel] = lipgloss.NewStyle().SetString("[?]").Foreground(lipgloss.Color("#6c7086"))
	s.Levels[log.InfoLevel] = lipgloss.NewStyle().SetString("[+]").Foreground(lipgloss.Color("#74c7ec"))
	s.Levels[log.WarnLevel] = lipgloss.NewStyle().SetString("[!]").Foreground(lipgloss.Color("#f9e2af"))
	s.Levels[log.ErrorLevel] = lipgloss.NewStyle().SetString("[x]").Foreground(lipgloss.Color("#f38ba8"))

	s.Key = lipgloss.NewStyle().Foreground(lipgloss.Color("#6c7086"))
	s.Value = lipgloss.NewStyle().Foreground(lipgloss.Color("#b4befe"))

	hexTransform := lipgloss.NewStyle().Foreground(lipgloss.Color("#fab387")).Transform(func(v string) string {
		if num, err := strconv.ParseUint(v, 0, 64); err == nil {
			return fmt.Sprintf("0x%x", num)
		}
		return v
	})
	for _, key := range []string{"vaddr", "paddr", "addr", "offset", "base", "from", "to", "end", "start", "handle", "mmap_addr", "mmap_region", "input_path", "output_path", "path"} {
		s.Values[key] = hexTransform
	}
	for _, key := range []string{"index", "size", "memory_size", "file_size", "count", "entry_count", "entries", "total_size", "expected_count", "actual_count", "decoded_count", "section_count", "symbol_count", "program_header_count"} {
		s.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#CBA6F7"))
	}
	for _, key := range []string{"type", "tag", "reloc", "bind", "flags", "level"} {
		s.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa")).Bold(true)
	}
	for _, key := range []string{"file", "path", "runpath", "input_path", "output_path"} {
		s.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#f9e2af"))
	}
	for _, key := range []string{"name", "symbol", "sym", "lib", "library", "section", "section1", "section2", "package", "tag"} {
		s.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1"))
	}
	return s
}

func newLogger(verbosity int) (*log.Logger, error) {
	var level log.Level
	switch verbosity {
	case 0:
		level = log.WarnLevel
	case 1:
		level = log.InfoLevel
	case 2:
		level = log.DebugLevel
	default:
		return nil, fmt.Errorf("invalid verbosity %d (expected 0, 1, or 2)", verbosity)
	}
	lg := log.NewWithOptions(os.Stdout, log.Options{ReportTimestamp: false, ReportCaller: false})
	lg.SetStyles(styles())
	lg.SetLevel(level)
	return lg, nil
}

// FixELFHeaders attempts to fix common issues with ELF headers.
// verbosity: 0=quiet (warn only), 1=info, 2=debug.
//
// Returns the post-fix verification issues (empty when the rebuilt ELF is
// clean) and any fatal error. A nil error with a non-empty issues slice means
// the output was written but the verifier flagged residual problems (e.g.
// un-normalised pointers).
func FixELFHeaders(filePath string, baseAddr uint64, outputPath string, verbosity int) ([]string, error) {
	lg, err := newLogger(verbosity)
	if err != nil {
		return nil, err
	}
	lg.Info("elf fix", "path", filePath, "base", baseAddr)

	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := ElfReader{
		File:      file,
		ElfHeader: new(Elf64_Ehdr),
		BaseAddr:  baseAddr,
		logger:    lg,
	}

	if err := reader.Read(); err != nil {
		return nil, err
	}

	rebuilder, err := NewElfRebuilder(&reader, outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create rebuilder: %w", err)
	}
	defer rebuilder.OutFile.Close()

	if err := rebuilder.WriteFixedElf(); err != nil {
		lg.Error("elf fin", "error", err, "output_path", outputPath)
		return nil, err
	}

	// Close the writer side before re-opening for verification so the writes
	// are durably visible. Re-closing on the defer is harmless.
	if err := rebuilder.OutFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close output: %w", err)
	}

	// Post-fix verification on the closed output file
	var issues []string
	if info, statErr := os.Stat(outputPath); statErr == nil {
		issues = CheckFixedElf(lg, outputPath, baseAddr, uint64(info.Size()))
	}

	lg.Info("elf fin", "output_path", outputPath)
	return issues, nil
}

// readArray reads up to 'count' elements of type T from file at the given offset.
// Returns the successfully read elements. On EOF, returns partial results without error.
// count is clamped against the remaining file size to defend against corrupt sizing
// fields that would otherwise trigger an OOM allocation.
func readArray[T any](lg *log.Logger, file *os.File, offset uint64, count uint64, name string) ([]T, error) {
	if count == 0 {
		return []T{}, nil
	}

	var zero T
	elemSize := uint64(binary.Size(zero))
	if elemSize == 0 {
		return nil, fmt.Errorf("readArray %s: cannot determine element size", name)
	}

	if info, err := file.Stat(); err == nil {
		fileSize := uint64(info.Size())
		if offset >= fileSize {
			return nil, fmt.Errorf("readArray %s: offset 0x%x past file size 0x%x", name, offset, fileSize)
		}
		maxCount := (fileSize - offset) / elemSize
		if count > maxCount {
			lg.Warn("readArray clamp", "name", name, "requested", count, "max", maxCount)
			count = maxCount
		}
	}

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
				if len(result) > 0 {
					lg.Warn("partial read", "name", name, "expected_count", count, "actual_count", len(result))
				}
				return result, nil
			}
			return nil, fmt.Errorf("failed to read %s element %d at 0x%x: %w", name, i, offset, err)
		}
		result = append(result, elem)
	}

	return result, nil
}
