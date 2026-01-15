package main

/*
#include <stdlib.h>
#include <string.h>

// Entry point for CLI execution when loaded as a shared library
// This is called when the .so is executed directly
extern void runCLI(int argc, char** argv);
*/
import "C"
import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"unsafe"

	pkg "github.com/Arsylk/gosofix/pkg"
)

// runCLI is the entry point when the shared library is executed directly.
// It's called from the library's constructor or via the interp handler.
//
//export runCLI
func runCLI(argc C.int, argv **C.char) {
	// Reconstruct os.Args from C arguments
	args := make([]string, int(argc))
	cArgv := unsafe.Slice(argv, int(argc))
	for i, arg := range cArgv {
		args[i] = C.GoString(arg)
	}
	os.Args = args

	// Run the CLI
	cliMain()
}

// The returned C string must be freed by the caller.
//
//export FixElf
func FixElf(inputPath *C.char, memAddr uint64, outputPath *C.char) *C.char {
	goInputPath := C.GoString(inputPath)
	if goInputPath == "" {
		return C.CString("missng input file")
	}

	goOutputPath := C.GoString(outputPath)
	if goOutputPath == "" {
		goOutputPath = autogenerateOutputPath(goInputPath)
	}

	var err error
	if memAddr == 0 {
		memAddr, err = autoparseMemAddr(goInputPath)
		if memAddr == 0 || err != nil {
			return C.CString("incorrect memory addr")
		}
	}

	err, msg := pkg.FixELFHeaders(goInputPath, memAddr, goOutputPath, 0)
	if err != nil {
		return C.CString(fmt.Sprintf("error fixing elf: %v", err))
	}

	return C.CString(msg)
}

func main() {
	// main() is not called when built with -buildmode=c-shared
	// CLI functionality is accessed via the runCLI export
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
	argIdx := 0

	if version {
		fmt.Println("gosofix v0.0.4")
		os.Exit(0)
	}

	exitUsage := func(msg string) {
		fmt.Printf("error: %s\n", msg)
		fmt.Println("usage: gosofix [-v <level>] <in_file> [<mem_address>] [out_file]")
		fmt.Println("  --version   Show version information")
		fmt.Println("  -v <level>  Verbosity level (0=quiet, 1=info, 2=debug)")
		fmt.Println("  -i <in_file>   Input file")
		fmt.Println("  -m <mem_addr>   Memory address")
		fmt.Println("  -o <out_file>   Output file")
		os.Exit(1)
	}
	if inputPath == "" {
		inputPath = flag.Arg(argIdx)
		if inputPath == "" {
			exitUsage("missng input file")
		}
		argIdx += 1
	}

	if memAddr == 0 {
		var err error
		memAddrStr := flag.Arg(argIdx)
		if memAddrStr == "" {
			memAddrStr = inputPath
		}
		memAddr, err = autoparseMemAddr(memAddrStr)
		if memAddr == 0 || err != nil {
			exitUsage("incorrect memory addr")
		}
		argIdx += 1
	}

	if outputPath == "" {
		outputPath = flag.Arg(argIdx)
		if outputPath == "" {
			outputPath = autogenerateOutputPath(inputPath)
		}
	}

	err, msg := pkg.FixELFHeaders(inputPath, memAddr, outputPath, verbosity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fixing elf: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", msg)
}

func autogenerateOutputPath(inputPath string) string {
	path := filepath.Base(inputPath)
	return path[:len(path)-len(filepath.Ext(path))] + "_fix" + filepath.Ext(path)
}

var hexAddrRegex = regexp.MustCompile(`0x[0-9a-fA-F]+`)

func autoparseMemAddr(addrStr string) (uint64, error) {
	if match := hexAddrRegex.FindString(addrStr); match != "" {
		return strconv.ParseUint(match, 0, 64)
	}
	return strconv.ParseUint(addrStr, 16, 64)
}
