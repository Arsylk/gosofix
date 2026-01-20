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

// FixElf is the exported function for the shared library.
// The returned C string must be freed by the caller.
//
//export FixElf
func FixElf(inputPath *C.char, memAddr uint64, outputPath *C.char) *C.char {
	goInputPath := C.GoString(inputPath)
	goOutputPath := C.GoString(outputPath)

	err, msg := fixElf(goInputPath, memAddr, goOutputPath, 0)
	if err != nil {
		return C.CString(fmt.Sprintf("error: %v", err))
	}

	return C.CString(msg)
}

// fixElf is the shared logic for both CLI and Library.
func fixElf(inputPath string, memAddr uint64, outputPath string, verbosity int) (error, string) {
	if inputPath == "" {
		return fmt.Errorf("missing input file"), ""
	}

	if memAddr == 0 {
		var err error
		memAddr, err = autoparseMemAddr(inputPath)
		if err != nil || memAddr == 0 {
			return fmt.Errorf("incorrect memory addr"), ""
		}
	}

	if outputPath == "" {
		outputPath = autogenerateOutputPath(inputPath)
	}

	return pkg.FixELFHeaders(inputPath, memAddr, outputPath, verbosity)
}

func cliMain() {
	var verbosity int
	var version bool
	var memAddr uint64
	var inputPath string
	var outputPath string

	flag.BoolVar(&version, "version", false, "Show version information")
	flag.IntVar(&verbosity, "v", 0, "Verbosity level (0=quiet, 1=info, 2=debug, 3=trace)")
	flag.StringVar(&inputPath, "i", "", "Input file")
	flag.Uint64Var(&memAddr, "m", 0, "Memory address")
	flag.StringVar(&outputPath, "o", "", "Output file")
	flag.Parse()

	if version {
		fmt.Println("gosofix v0.0.4")
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
		if addr, err := autoparseMemAddr(flag.Arg(argIdx)); err == nil {
			memAddr = addr
			argIdx++
		}
	}

	if outputPath == "" {
		outputPath = flag.Arg(argIdx)
	}

	err, msg := fixElf(inputPath, memAddr, outputPath, verbosity)
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

func autoparseMemAddr(addrStr string) (uint64, error) {
	if match := hexAddrRegex.FindString(addrStr); match != "" {
		return strconv.ParseUint(match, 0, 64)
	}
	return strconv.ParseUint(addrStr, 16, 64)
}

func main() {
	cliMain()
}
