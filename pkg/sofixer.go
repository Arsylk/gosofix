// Package sofixer normalizes Android ARM64 (AArch64) ELF shared-object memory
// dumps back into valid ELF files for static analysis. A dump captures the
// post-relocation image at a runtime base address; sofixer reverses the dynamic
// linker's fixups (relocations, GOT/PLT slots, init arrays) to base-independent
// offsets, reconstructs section headers from the dynamic segment, and writes a
// tool-loadable ELF. It targets ET_DYN AArch64 objects only.
package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/muesli/termenv"
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
	for _, key := range []string{"vaddr", "paddr", "addr", "offset", "base", "from", "to", "end", "start", "handle", "mmap_addr", "mmap_region"} {
		s.Values[key] = hexTransform
	}
	for _, key := range []string{"index", "size", "memory_size", "file_size", "count", "entry_count", "entries", "total_size", "expected_count", "actual_count", "decoded_count", "section_count", "symbol_count", "program_header_count"} {
		s.Values[key] = lipgloss.NewStyle().Foreground(lipgloss.Color("#CBA6F7"))
	}
	for _, key := range []string{"type", "reloc", "bind", "flags", "level"} {
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
	// Forced color must retain our RGB palette when output is captured by a
	// host tool. termenv otherwise falls back to 16-color ANSI on pipes.
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		lg.SetColorProfile(termenv.Ascii)
	} else if forced := os.Getenv("CLICOLOR_FORCE"); forced != "" && forced != "0" {
		lg.SetColorProfile(termenv.TrueColor)
	}
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
	if outputPath == "" {
		return nil, fmt.Errorf("missing output file")
	}
	lg.Info("elf fix", "path", filePath, "base", baseAddr)

	same, err := pathsReferToSameFile(filePath, outputPath)
	if err != nil {
		return nil, err
	}
	if same {
		return nil, fmt.Errorf("input and output refer to the same file")
	}

	file, err := os.Open(filePath)
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

	temp, err := os.CreateTemp(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary output: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temporary output: %w", err)
	}
	if err := os.Chmod(tempPath, 0o644); err != nil {
		return nil, fmt.Errorf("failed to set output mode: %w", err)
	}

	rebuilder, err := NewElfRebuilder(&reader, tempPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create rebuilder: %w", err)
	}
	if err := rebuilder.WriteFixedElf(); err != nil {
		rebuilder.OutFile.Close()
		lg.Error("elf fin", "error", err, "output_path", outputPath)
		return nil, err
	}
	if err := rebuilder.OutFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close output: %w", err)
	}

	issues := CheckFixedElf(lg, tempPath, baseAddr)
	if err := os.Rename(tempPath, outputPath); err != nil {
		return nil, fmt.Errorf("failed to install output: %w", err)
	}

	lg.Info("elf fin", "output_path", outputPath)
	return issues, nil
}

func pathsReferToSameFile(inputPath, outputPath string) (bool, error) {
	inputInfo, err := os.Stat(inputPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat input: %w", err)
	}
	if outputInfo, err := os.Stat(outputPath); err == nil {
		return os.SameFile(inputInfo, outputInfo), nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to stat output: %w", err)
	}

	inputAbs, err := filepath.Abs(inputPath)
	if err != nil {
		return false, fmt.Errorf("failed to resolve input path: %w", err)
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return false, fmt.Errorf("failed to resolve output path: %w", err)
	}
	return filepath.Clean(inputAbs) == filepath.Clean(outputAbs), nil
}

// readArray reads exactly 'count' elements of type T from file at the given
// offset. A truncated table is a fatal format error; callers depend on the
// returned slice length matching the advertised ELF metadata.
func readArray[T any](file *os.File, offset uint64, count uint64, name string) ([]T, error) {
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
			return nil, fmt.Errorf("readArray %s: truncated table requested=%d max=%d elem_size=%d", name, count, maxCount, elemSize)
		}
	}

	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to %s at 0x%x: %w", name, offset, err)
	}

	array := make([]T, count)
	if err := binary.Read(file, binary.LittleEndian, array); err != nil {
		return nil, fmt.Errorf("failed to read %s at 0x%x count=%d: %w", name, offset, count, err)
	}

	return array, nil
}
