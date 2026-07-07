package tests

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	sofixer "github.com/Arsylk/gosofix/pkg"
)

// putStruct binary-encodes v (little-endian) into buf at off.
func putStruct(t *testing.T, buf []byte, off int, v any) {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
		t.Fatal(err)
	}
	copy(buf[off:], b.Bytes())
}

// buildRelrDumpImage hand-builds a minimal ARM64 ET_DYN "memory dump": an image
// laid out linearly by (normalized) vaddr, with every address stored as an
// absolute runtime address (base + offset), exactly as a real dump would look.
// It carries a single RELR relocation whose target slot holds an in-image
// pointer, so the full FixELFHeaders pipeline (header/phdr/dynamic/RELR/section
// reconstruction) is exercised end to end.
func buildRelrDumpImage(t *testing.T, base uint64) []byte {
	t.Helper()
	const (
		imgSize    = 0x1000
		offDynstr  = 0x100
		offDynsym  = 0x120
		offHash    = 0x140
		offDynamic = 0x200
		offRelr    = 0x300
		offSlot    = 0x400
		slotTarget = 0x408 // where the RELR-relocated pointer points (in-image)
	)
	buf := make([]byte, imgSize)

	// ELF header.
	ehdr := sofixer.Elf64_Ehdr{
		Magic:        [4]byte{0x7f, 'E', 'L', 'F'},
		Class:        2, // ELFCLASS64
		Data:         1, // ELFDATA2LSB
		IdentVersion: 1,
		Type:         3,   // ET_DYN
		Machine:      183, // EM_AARCH64
		Version:      1,
		Entry:        base, // absolute; normalized to 0 by the reader
		PhdrOffset:   0x40,
		Ehsize:       64,
		Phentsize:    56,
		Phnum:        2,
	}
	putStruct(t, buf, 0, &ehdr)

	// Program headers: one RW PT_LOAD covering the image, plus PT_DYNAMIC.
	phdrs := []sofixer.Elf64_Phdr{
		{Type: 1 /*PT_LOAD*/, Flags: 6 /*R|W*/, Offset: 0, Vaddr: base, Paddr: base, Filesz: imgSize, Memsz: imgSize, Align: 0x1000},
		{Type: 2 /*PT_DYNAMIC*/, Flags: 6, Offset: offDynamic, Vaddr: base + offDynamic, Paddr: base + offDynamic, Filesz: 0x90, Memsz: 0x90, Align: 8},
	}
	putStruct(t, buf, 0x40, phdrs)

	// .dynstr (8 bytes, empty string at index 0). .dynsym (one null symbol).
	// .hash with Nbucket=1, Nchain=1 => symbol count 1.
	binary.LittleEndian.PutUint32(buf[offHash+0:], 1)  // nbucket
	binary.LittleEndian.PutUint32(buf[offHash+4:], 1)  // nchain
	binary.LittleEndian.PutUint32(buf[offHash+8:], 0)  // bucket[0]
	binary.LittleEndian.PutUint32(buf[offHash+12:], 0) // chain[0]

	// Dynamic section: addresses are absolute (base+off), normalized by the reader.
	dyns := []sofixer.Elf64_Dyn{
		{Tag: 5 /*DT_STRTAB*/, Val: base + offDynstr},
		{Tag: 10 /*DT_STRSZ*/, Val: 8},
		{Tag: 6 /*DT_SYMTAB*/, Val: base + offDynsym},
		{Tag: 11 /*DT_SYMENT*/, Val: 24},
		{Tag: 4 /*DT_HASH*/, Val: base + offHash},
		{Tag: 36 /*DT_RELR*/, Val: base + offRelr},
		{Tag: 35 /*DT_RELRSZ*/, Val: 8},
		{Tag: 37 /*DT_RELRENT*/, Val: 8},
		{Tag: 0 /*DT_NULL*/, Val: 0},
	}
	putStruct(t, buf, offDynamic, dyns)

	// RELR: a single even (anchor) entry = absolute address of the slot to patch.
	binary.LittleEndian.PutUint64(buf[offRelr:], base+offSlot)
	// The relocated slot holds an absolute in-image pointer.
	binary.LittleEndian.PutUint64(buf[offSlot:], base+slotTarget)

	return buf
}

func TestFixELFHeadersRelrEndToEnd(t *testing.T) {
	const base = uint64(0x7000000000)
	const offSlot = 0x400
	const slotTarget = 0x408

	img := buildRelrDumpImage(t, base)
	dir := t.TempDir()
	in := filepath.Join(dir, "relr_dump.so")
	out := filepath.Join(dir, "relr_fixed.so")
	if err := os.WriteFile(in, img, 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := sofixer.FixELFHeaders(in, base, out, 0)
	if err != nil {
		t.Fatalf("FixELFHeaders failed: %v", err)
	}
	for _, iss := range issues {
		t.Errorf("verifier flagged an issue on synthetic RELR ELF: %s", iss)
	}

	// The RELR-relocated slot must be normalized from base+target to target.
	fixed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) < offSlot+8 {
		t.Fatalf("output too small: %d bytes", len(fixed))
	}
	if got := binary.LittleEndian.Uint64(fixed[offSlot:]); got != slotTarget {
		t.Fatalf("RELR slot = 0x%x, want 0x%x (normalized)", got, slotTarget)
	}

	// The rebuilt ELF must be structurally valid to a standard tool.
	if _, err := exec.LookPath("readelf"); err == nil {
		for _, args := range [][]string{{"-h", out}, {"-l", out}, {"-S", out}, {"-d", out}, {"-r", out}} {
			if o, err := exec.Command("readelf", args...).CombinedOutput(); err != nil {
				t.Errorf("readelf %v failed: %v\n%s", args, err, o)
			}
		}
	}
}
