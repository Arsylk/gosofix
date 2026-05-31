package tests

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sofixer "github.com/Arsylk/gosofix/pkg"
)

// ============================================================
// Unit Tests
// ============================================================

// TestRelocationConstants locks the on-the-wire values for the AArch64
// dynamic relocation types against the ARM ELF ABI (IHI 0056F §4.6.6).
// Catches regressions like the historic R_AARCH64_COPY = 0x108 typo.
func TestRelocationConstants(t *testing.T) {
	cases := []struct {
		name string
		got  sofixer.RelocationType
		want uint32
	}{
		{"COPY", sofixer.R_AARCH64_COPY, 1024},
		{"GLOB_DAT", sofixer.R_AARCH64_GLOB_DAT, 1025},
		{"JUMP_SLOT", sofixer.R_AARCH64_JUMP_SLOT, 1026},
		{"RELATIVE", sofixer.R_AARCH64_RELATIVE, 1027},
		{"TLS_DTPMOD", sofixer.R_AARCH64_TLS_DTPMOD, 1028},
		{"TLS_DTPREL", sofixer.R_AARCH64_TLS_DTPREL, 1029},
		{"TLS_TPREL", sofixer.R_AARCH64_TLS_TPREL, 1030},
		{"TLSDESC", sofixer.R_AARCH64_TLSDESC, 1031},
		{"IRELATIVE", sofixer.R_AARCH64_IRELATIVE, 1032},
		{"ABS64", sofixer.R_AARCH64_ABS64, 257},
		{"PREL64", sofixer.R_AARCH64_PREL64, 260},
	}
	for _, tc := range cases {
		if uint32(tc.got) != tc.want {
			t.Errorf("R_AARCH64_%s = %d (0x%x), want %d (0x%x)",
				tc.name, uint32(tc.got), uint32(tc.got), tc.want, tc.want)
		}
	}
}

func TestIsDataRelocation(t *testing.T) {
	tests := []struct {
		typ  sofixer.RelocationType
		ok   bool
		name string
	}{
		{sofixer.R_AARCH64_NONE, false, "NONE"},
		{sofixer.R_AARCH64_ABS64, true, "ABS64"},
		{sofixer.R_AARCH64_PREL64, true, "PREL64"},
		{sofixer.R_AARCH64_RELATIVE, true, "RELATIVE"},
		{sofixer.R_AARCH64_GLOB_DAT, true, "GLOB_DAT"},
		{sofixer.R_AARCH64_JUMP_SLOT, true, "JUMP_SLOT"},
		{sofixer.R_AARCH64_COPY, true, "COPY"},
		{sofixer.R_AARCH64_TLS_DTPMOD, true, "TLS_DTPMOD"},
		{sofixer.R_AARCH64_TLS_DTPREL, true, "TLS_DTPREL"},
		{sofixer.R_AARCH64_TLS_TPREL, true, "TLS_TPREL"},
		{sofixer.R_AARCH64_TLSDESC, true, "TLSDESC"},
		{sofixer.R_AARCH64_IRELATIVE, true, "IRELATIVE"},
		{sofixer.R_AARCH64_CALL26, false, "CALL26"},
		{sofixer.R_AARCH64_JUMP26, false, "JUMP26"},
		{sofixer.R_AARCH64_ADR_PREL21, false, "ADR_PREL21"},
		{sofixer.RelocationType(0xDEAD), false, "UNKNOWN"},
	}
	for _, tt := range tests {
		got := _isDataRelocationHelper(tt.typ)
		if got != tt.ok {
			t.Errorf("isDataRelocation(%s)=%v, want %v", tt.name, got, tt.ok)
		}
	}
}

// Helper: mirrors pkg.isDataRelocation since it's unexported.
func _isDataRelocationHelper(rt sofixer.RelocationType) bool {
	switch rt {
	case sofixer.R_AARCH64_NONE:
		return false
	case sofixer.R_AARCH64_ABS64, sofixer.R_AARCH64_PREL64, sofixer.R_AARCH64_RELATIVE,
		sofixer.R_AARCH64_GLOB_DAT, sofixer.R_AARCH64_JUMP_SLOT, sofixer.R_AARCH64_COPY,
		sofixer.R_AARCH64_TLS_DTPMOD, sofixer.R_AARCH64_TLS_DTPREL, sofixer.R_AARCH64_TLS_TPREL,
		sofixer.R_AARCH64_TLSDESC, sofixer.R_AARCH64_IRELATIVE:
		return true
	default:
		return false
	}
}

func TestDecodeSLEB128(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want int64
		n    int
	}{
		{"zero", []byte{0x00}, 0, 1},
		{"one", []byte{0x01}, 1, 1},
		{"neg_one", []byte{0x7f}, -1, 1},
		{"128", []byte{0x80, 0x01}, 128, 2},
		{"neg_two", []byte{0x7e}, -2, 1},
		{"neg_127", []byte{0x81, 0x7f}, -127, 2},
		{"twelve", []byte{0x0c}, 12, 1},
		// Empty input: returns zero with zero bytes consumed.
		{"empty", []byte{}, 0, 0},
		// Malformed: never-terminating continuation bytes. Bails after 10 bytes.
		{"runaway", bytes.Repeat([]byte{0x80}, 32), 0, 10},
	}
	for _, tt := range tests {
		got, n := sofixer.DecodeSLEB128(tt.raw)
		if got != tt.want || n != tt.n {
			t.Errorf("DecodeSLEB128(%s) = (%d,%d), want (%d,%d)",
				tt.name, got, n, tt.want, tt.n)
		}
	}
}

func TestDemangleSymbol(t *testing.T) {
	if got := sofixer.DemangleSymbol("_Z3foov"); got != "foo()" {
		t.Errorf("_Z3foov -> %q, want \"foo()\"", got)
	}
	if got := sofixer.DemangleSymbol("plain_name"); got != "plain_name" {
		t.Errorf("plain_name -> %q, want \"plain_name\"", got)
	}
}

func TestAlignUp(t *testing.T) {
	cases := []struct{ val, align, want uint64 }{
		{0, 8, 0}, {1, 8, 8}, {7, 8, 8}, {8, 8, 8}, {9, 8, 16},
		{0, 0, 0},
	}
	for _, c := range cases {
		if got := sofixer.AlignUp(c.val, c.align); got != c.want {
			t.Errorf("AlignUp(%d,%d)=%d, want %d", c.val, c.align, got, c.want)
		}
	}
}

// validElfHeader returns a 64-byte ELF64 AArch64 ET_DYN header that passes
// every ReadElfHeader validation. Per-test mutations live next to their case.
func validElfHeader() []byte {
	b := make([]byte, 64)
	copy(b[0:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2                                     // EI_CLASS = ELFCLASS64
	b[5] = 1                                     // EI_DATA  = little endian
	b[6] = 1                                     // EI_VERSION
	binary.LittleEndian.PutUint16(b[16:18], 3)   // e_type = ET_DYN
	binary.LittleEndian.PutUint16(b[18:20], 183) // e_machine = EM_AARCH64
	binary.LittleEndian.PutUint32(b[20:24], 1)   // e_version
	binary.LittleEndian.PutUint16(b[52:54], 64)  // e_ehsize
	binary.LittleEndian.PutUint16(b[54:56], 56)  // e_phentsize
	binary.LittleEndian.PutUint16(b[56:58], 0)   // e_phnum (zero → triggers phdr error, but it's our error)
	return b
}

func writeTempELF(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.so")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFixELFHeaders_ErrorPaths(t *testing.T) {
	outDir := t.TempDir()
	out := filepath.Join(outDir, "out.so")

	t.Run("missing file", func(t *testing.T) {
		_, err := sofixer.FixELFHeaders("/nonexistent/path.so", 0x1000, out, 0)
		if err == nil {
			t.Fatal("expected error for missing input")
		}
	})

	t.Run("invalid verbosity", func(t *testing.T) {
		_, err := sofixer.FixELFHeaders("/dev/null", 0x1000, out, 99)
		if err == nil || !strings.Contains(err.Error(), "invalid verbosity") {
			t.Fatalf("expected verbosity error, got: %v", err)
		}
	})

	t.Run("bad magic", func(t *testing.T) {
		hdr := validElfHeader()
		hdr[0] = 'X'
		_, err := sofixer.FixELFHeaders(writeTempELF(t, hdr), 0x1000, out, 0)
		if err == nil || !strings.Contains(err.Error(), "magic") {
			t.Fatalf("expected magic error, got: %v", err)
		}
	})

	t.Run("ELF32 rejected", func(t *testing.T) {
		hdr := validElfHeader()
		hdr[4] = 1 // ELFCLASS32
		_, err := sofixer.FixELFHeaders(writeTempELF(t, hdr), 0x1000, out, 0)
		if err == nil || !strings.Contains(err.Error(), "class") {
			t.Fatalf("expected class error, got: %v", err)
		}
	})

	t.Run("wrong architecture", func(t *testing.T) {
		hdr := validElfHeader()
		binary.LittleEndian.PutUint16(hdr[18:20], 62) // EM_X86_64
		_, err := sofixer.FixELFHeaders(writeTempELF(t, hdr), 0x1000, out, 0)
		if err == nil || !strings.Contains(err.Error(), "architecture") {
			t.Fatalf("expected architecture error, got: %v", err)
		}
	})

	t.Run("invalid version", func(t *testing.T) {
		hdr := validElfHeader()
		hdr[6] = 0
		_, err := sofixer.FixELFHeaders(writeTempELF(t, hdr), 0x1000, out, 0)
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Fatalf("expected version error, got: %v", err)
		}
	})

	t.Run("wrong ehsize", func(t *testing.T) {
		hdr := validElfHeader()
		binary.LittleEndian.PutUint16(hdr[52:54], 52) // ELF32 size
		_, err := sofixer.FixELFHeaders(writeTempELF(t, hdr), 0x1000, out, 0)
		if err == nil || !strings.Contains(err.Error(), "header size") {
			t.Fatalf("expected ehsize error, got: %v", err)
		}
	})

	t.Run("wrong phentsize", func(t *testing.T) {
		hdr := validElfHeader()
		binary.LittleEndian.PutUint16(hdr[54:56], 32)
		_, err := sofixer.FixELFHeaders(writeTempELF(t, hdr), 0x1000, out, 0)
		if err == nil || !strings.Contains(err.Error(), "program header entry size") {
			t.Fatalf("expected phentsize error, got: %v", err)
		}
	})

	t.Run("ET_EXEC rejected", func(t *testing.T) {
		hdr := validElfHeader()
		binary.LittleEndian.PutUint16(hdr[16:18], 2) // ET_EXEC
		_, err := sofixer.FixELFHeaders(writeTempELF(t, hdr), 0x1000, out, 0)
		if err == nil || !strings.Contains(err.Error(), "type") {
			t.Fatalf("expected type error, got: %v", err)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		_, err := sofixer.FixELFHeaders(writeTempELF(t, []byte{0x7f, 'E', 'L', 'F'}), 0x1000, out, 0)
		if err == nil {
			t.Fatal("expected error for truncated header")
		}
	})
}

func TestSymbolBindType(t *testing.T) {
	var sym sofixer.Elf64_Sym
	sym.St_Info = (uint8(sofixer.STB_GLOBAL) << 4) | uint8(sofixer.STT_FUNC)
	if got := sym.StBind(); got != sofixer.STB_GLOBAL {
		t.Errorf("stBind: got %v, want STB_GLOBAL", got)
	}
	if got := sym.StType(); got != sofixer.STT_FUNC {
		t.Errorf("stType: got %v, want STT_FUNC", got)
	}
}

// ============================================================
// Sample dump regression tests
// ============================================================

func testFixAndVerify(t *testing.T, inputPath string, baseAddr uint64, label string) string {
	t.Helper()
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.so")
	issues, err := sofixer.FixELFHeaders(inputPath, baseAddr, outputPath, 0)
	if err != nil {
		t.Fatalf("[%s] FixELFHeaders failed: %v", label, err)
	}
	t.Logf("[%s] output=%s", label, outputPath)
	for _, iss := range issues {
		t.Logf("[%s] verifier: %s", label, iss)
	}
	info, err := os.Stat(outputPath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("[%s] output missing or empty", label)
	}
	return outputPath
}

func TestSampleDumps(t *testing.T) {
	if _, err := exec.LookPath("readelf"); err != nil {
		t.Skip("readelf not in PATH; skipping sample regression tests")
	}
	repoRoot := "../samples"

	samples := []struct {
		file string
		base uint64
		name string
	}{
		{"libjiagu.so_dump_0x759b2b2000.so", 0x759b2b2000, "jiagu"},
		{"libdexprotector.so_dump_0x6ddc6d8000.so", 0x6ddc6d8000, "dexprotector"},
		{"saitcza.so_dump_0x76c8436000.so", 0x76c8436000, "saitcza"},
		{"libstubiest.so_dump_0x7572b00000.so", 0x7572b00000, "stubiest"},
		{"libSt9w.so_dump_0x7366c6e000.so", 0x7366c6e000, "St9w"},
		{"libriskdetector.so_dump_0x6f3d8f4000.so", 0x6f3d8f4000, "riskdetector"},
		{"libhunter.so_dump_0x6bfda14000.so", 0x6bfda14000, "hunter"},
		{"libuseard.so_dump_0x71fcfa8000.so", 0x71fcfa8000, "useard"},
	}

	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			inputPath := filepath.Join(repoRoot, s.file)
			if _, err := os.Stat(inputPath); os.IsNotExist(err) {
				t.Skipf("sample %s not found", s.file)
			}

			outputPath := testFixAndVerify(t, inputPath, s.base, s.name)

			// Verify ELF header
			f, err := os.Open(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			var ehdr sofixer.Elf64_Ehdr
			if err := binary.Read(f, binary.LittleEndian, &ehdr); err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()

			if ehdr.Magic != [4]byte{0x7f, 'E', 'L', 'F'} {
				t.Error("bad magic")
			}
			if ehdr.Class != 2 {
				t.Error("not 64-bit")
			}
			if ehdr.Machine != 183 {
				t.Error("not AArch64")
			}
			if ehdr.Phnum == 0 {
				t.Error("no program headers")
			}
			if ehdr.Type != 3 {
				t.Errorf("expected ET_DYN(3), got %d", ehdr.Type)
			}
			if ehdr.Shnum == 0 {
				t.Error("section header count is zero")
			}

			// Verify dynamic section has key tags
			dynOut, err := exec.Command("readelf", "-d", outputPath).CombinedOutput()
			if err != nil {
				t.Errorf("readelf -d failed: %v", err)
				return
			}
			if s := string(dynOut); !strings.Contains(s, "SYMTAB") || !strings.Contains(s, "STRTAB") {
				t.Error("dynamic section missing SYMTAB or STRTAB")
			}

			// Verify section headers
			secOut, err := exec.Command("readelf", "-S", outputPath).CombinedOutput()
			if err != nil {
				t.Errorf("readelf -S failed: %v", err)
				return
			}
			secStr := string(secOut)
			for _, name := range []string{".dynsym", ".dynstr", ".shstrtab"} {
				if !strings.Contains(secStr, name) {
					t.Errorf("output missing section %q", name)
				}
			}

			// Verify defined function symbols have valid section indices
			symOut, err := exec.Command("readelf", "--dyn-syms", outputPath).CombinedOutput()
			if err != nil {
				t.Errorf("readelf --dyn-syms failed: %v", err)
				return
			}
			for _, line := range strings.Split(string(symOut), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 8 && strings.Contains(line, "FUNC") && !strings.Contains(line, "UND") {
					ndx := fields[6]
					if ndx == "0" || ndx == "UND" {
						t.Errorf("defined function symbol has invalid section index (Ndx=%s): %s", ndx, line)
					}
				}
			}

			// Verify all readelf invocations succeed
			for _, args := range [][]string{
				{"-h", outputPath},
				{"-l", outputPath},
				{"-S", outputPath},
				{"-d", outputPath},
				{"--dyn-syms", outputPath},
				{"-r", outputPath},
			} {
				if out, err := exec.Command("readelf", args...).CombinedOutput(); err != nil {
					t.Errorf("readelf %v failed: %v\n%s", args, err, out)
				}
			}
		})
	}
}
