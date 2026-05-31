package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	pkg "github.com/Arsylk/gosofix/pkg"
)

// FixElf is the quiet-mode shared-library entry. The returned C string must be
// freed by the caller.
//
//export FixElf
func FixElf(inputPath *C.char, memAddr uint64, outputPath *C.char) *C.char {
	return FixElfV(inputPath, memAddr, outputPath, 0)
}

// FixElfV is identical to FixElf but accepts an explicit verbosity level
// (0=warn, 1=info, 2=debug).
//
//export FixElfV
func FixElfV(inputPath *C.char, memAddr uint64, outputPath *C.char, verbosity C.int) *C.char {
	goInputPath := C.GoString(inputPath)
	goOutputPath := C.GoString(outputPath)

	msg, err := fixElf(goInputPath, memAddr, goOutputPath, int(verbosity))
	if err != nil {
		return C.CString(fmt.Sprintf("error: %v", err))
	}
	return C.CString(msg)
}

// fixElf is the shared logic for both CLI and Library.
func fixElf(inputPath string, memAddr uint64, outputPath string, verbosity int) (string, error) {
	if inputPath == "" {
		return "", fmt.Errorf("missing input file")
	}

	if memAddr == 0 {
		var err error
		memAddr, err = autoparseMemAddr(inputPath)
		if err != nil || memAddr == 0 {
			return "", fmt.Errorf("incorrect memory addr")
		}
	}

	if outputPath == "" {
		outputPath = autogenerateOutputPath(inputPath)
	}

	issues, err := pkg.FixELFHeaders(inputPath, memAddr, outputPath, verbosity)
	if err != nil {
		return "", err
	}
	if len(issues) > 0 {
		// Don't fail the CLI on residual-pointer or similar diagnostics — the
		// fixed file is still usable — but make them visible.
		for _, iss := range issues {
			fmt.Fprintf(os.Stderr, "warning: %s\n", iss)
		}
	}
	return "elf fin output_path=" + outputPath, nil
}

func cliMain() {
	var verbosity int
	var version bool
	var memAddr uint64
	var inputPath string
	var outputPath string

	flag.BoolVar(&version, "version", false, "Show version information")
	flag.IntVar(&verbosity, "v", 0, "Verbosity level (0=quiet, 1=info, 2=debug)")
	flag.StringVar(&inputPath, "i", "", "Input file")
	flag.Uint64Var(&memAddr, "m", 0, "Memory address")
	flag.StringVar(&outputPath, "o", "", "Output file")
	flag.Parse()

	if version {
		fmt.Println("gosofix v0.0.5")
		os.Exit(0)
	}

	// Support positional arguments as fallback
	argIdx := 0
	if inputPath == "" {
		inputPath = flag.Arg(argIdx)
		if inputPath != "" {
			argIdx++
		}
	}

	if memAddr == 0 && flag.Arg(argIdx) != "" {
		arg := flag.Arg(argIdx)
		addr, err := autoparseMemAddr(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: positional arg %q is not a hex address: %v\n", arg, err)
			os.Exit(1)
		}
		memAddr = addr
		argIdx++
	}

	if outputPath == "" {
		outputPath = flag.Arg(argIdx)
	}

	msg, err := fixElf(inputPath, memAddr, outputPath, verbosity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(msg)
}

func autogenerateOutputPath(inputPath string) string {
	ext := filepath.Ext(inputPath)
	base := inputPath[:len(inputPath)-len(ext)]
	return base + "_fix" + ext
}

var hexAddrRegex = regexp.MustCompile(`0x[0-9a-fA-F]+`)

// autoparseMemAddr extracts a base address from a filename or accepts a
// literal address. Requires an explicit `0x` prefix to avoid grabbing
// arbitrary hex-looking substrings of filenames.
func autoparseMemAddr(addrStr string) (uint64, error) {
	if match := hexAddrRegex.FindString(addrStr); match != "" {
		return strconv.ParseUint(match, 0, 64)
	}
	return 0, fmt.Errorf("no 0x-prefixed hex address found in %q", addrStr)
}

func main() {
	cliMain()
}
