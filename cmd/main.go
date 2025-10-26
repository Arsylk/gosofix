package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	pkg "github.com/Arsylk/gosofix/pkg"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "d", false, "Enable debug logging")
	flag.Parse()

	args := flag.Args()

	if len(args) < 2 {
		fmt.Println("Usage: SoFixer64 [-d] <elf_file> <base_address>")
		os.Exit(1)
	}

	filePath := args[0]
	baseAddrStr := args[1]

	// Parse base address. The '0' base allows for "0x" prefix for hex.
	baseAddr, err := strconv.ParseUint(baseAddrStr, 0, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid base address '%s': %v\n", baseAddrStr, err)
		os.Exit(1)
	}

	err = pkg.FixELFHeaders(filePath, baseAddr, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fixing ELF headers: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("ELF headers fixed successfully.")
}
