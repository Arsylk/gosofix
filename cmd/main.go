package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"

	pkg "github.com/Arsylk/gosofix/pkg"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "d", false, "Enable debug logging")
	flag.Parse()

	args := flag.Args()

	if len(args) < 2 {
		fmt.Println("Usage: SoFixer64 [-d] <elf_file> <base_address> [output_file]")
		os.Exit(1)
	}

	filePath := args[0]
	baseAddrStr := args[1]
	var outputPath string
	if len(args) > 2 {
		outputPath = args[2]
	} else {
		ext := path.Ext(filePath)
		if len(ext) == 0 {
			outputPath = filePath + "_fix.so"
		} else {

			outputPath = string([]rune(filePath)[0:len(filePath)-1-len(ext)]) + "_fix." + ext
		}
	}

	// Parse base address. The '0' base allows for "0x" prefix for hex.
	baseAddr, err := strconv.ParseUint(baseAddrStr, 0, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid base address '%s': %v\n", baseAddrStr, err)
		os.Exit(1)
	}

	err = pkg.FixELFHeaders(filePath, baseAddr, outputPath, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fixing ELF headers: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("ELF headers fixed at " + outputPath)
}
