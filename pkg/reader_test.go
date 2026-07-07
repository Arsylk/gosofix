package sofixer

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/log"
)

func appendTestSLEB(buf []byte, value int64) []byte {
	for {
		b := byte(value & 0x7f)
		signSet := (b & 0x40) != 0
		value >>= 7
		done := (value == 0 && !signSet) || (value == -1 && signSet)
		if !done {
			b |= 0x80
		}
		buf = append(buf, b)
		if done {
			return buf
		}
	}
}

func testRebuilderWithBytes(t *testing.T, data []byte) *ElfRebuilder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.so")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return &ElfRebuilder{
		ElfReader: &ElfReader{
			logger: log.NewWithOptions(io.Discard, log.Options{}),
		},
		OutFile:           f,
		sections:          make([]Elf64_Shdr, 0),
		shstrtab:          []byte{0},
		sectionNameMap:    make(map[string]uint32),
		sectionNameLookup: make(map[uint32]string),
	}
}

func testReaderForBlob(t *testing.T, blob []byte) (*ElfReader, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "packed.bin")
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return &ElfReader{
		File:   f,
		logger: log.NewWithOptions(io.Discard, log.Options{}),
	}, f
}

func TestDecodePackedRelaAPS2CumulativeAddends(t *testing.T) {
	blob := []byte("APS2")
	for _, v := range []int64{
		3, 0x1000,
		2, packedGroupedByInfo | packedGroupedByOffsetDelta | packedGroupHasAddend,
		8, int64(R_AARCH64_RELATIVE),
		0x10, 0x20,
		1, packedGroupedByInfo,
		int64(R_AARCH64_RELATIVE),
		0x10,
	} {
		blob = appendTestSLEB(blob, v)
	}

	r, _ := testReaderForBlob(t, blob)
	got, err := r.decodePackedRela(0, uint64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}

	wantOffsets := []uint64{0x1008, 0x1010, 0x1020}
	wantAddends := []int64{0x10, 0x30, 0}
	if len(got) != len(wantOffsets) {
		t.Fatalf("decoded %d relocs, want %d", len(got), len(wantOffsets))
	}
	for i := range got {
		if got[i].Offset != wantOffsets[i] || got[i].Addend != wantAddends[i] || got[i].Type() != R_AARCH64_RELATIVE {
			t.Fatalf("reloc[%d] = {off=0x%x type=%s add=%d}, want {off=0x%x type=%s add=%d}",
				i, got[i].Offset, got[i].Type().String(), got[i].Addend,
				wantOffsets[i], R_AARCH64_RELATIVE.String(), wantAddends[i])
		}
	}
}

func TestDecodePackedRelaRejectsTruncatedSLEB(t *testing.T) {
	blob := append([]byte("APS2"), 0x01)
	r, _ := testReaderForBlob(t, blob)
	_, err := r.decodePackedRela(0, uint64(len(blob)))
	if err == nil || !strings.Contains(err.Error(), "bad_sleb") {
		t.Fatalf("expected bad_sleb error, got %v", err)
	}
}

func TestDecodePackedRelRejectsAddends(t *testing.T) {
	blob := []byte("APS2")
	for _, v := range []int64{
		1, 0,
		1, packedGroupHasAddend,
	} {
		blob = appendTestSLEB(blob, v)
	}

	r, _ := testReaderForBlob(t, blob)
	_, err := r.decodePackedRel(0, uint64(len(blob)))
	if err == nil || !strings.Contains(err.Error(), "unexpected_addend") {
		t.Fatalf("expected unexpected_addend error, got %v", err)
	}
}

func TestReadRelocationTablesFailsOnBadAndroidPackedRel(t *testing.T) {
	blob := append([]byte{0}, []byte("APS2")...)
	blob = append(blob, 0x01)

	r, _ := testReaderForBlob(t, blob)
	r.androidRelVaddr = 1
	r.androidRelSize = uint64(len(blob) - 1)

	err := r.readRelocationTables()
	if err == nil || !strings.Contains(err.Error(), "android_rel decode") {
		t.Fatalf("expected android_rel decode error, got %v", err)
	}
}

func TestReadRelocationTablesRejectsDirtyAndroidPackedRel(t *testing.T) {
	blob := append([]byte{0}, []byte("APS2")...)
	for _, v := range []int64{
		1, 0x1000,
		1, packedGroupedByInfo | packedGroupedByOffsetDelta,
		0, int64(R_AARCH64_RELATIVE),
	} {
		blob = appendTestSLEB(blob, v)
	}

	r, _ := testReaderForBlob(t, blob)
	r.BaseAddr = 0x1000
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Vaddr: 0, Offset: 0, Memsz: 0x2000}}
	r.androidRelVaddr = 1
	r.androidRelSize = uint64(len(blob) - 1)

	err := r.readRelocationTables()
	if err == nil || !strings.Contains(err.Error(), "dirty_offsets") {
		t.Fatalf("expected dirty_offsets error, got %v", err)
	}
}

func TestNormalizeLoadedAddressUsesPTLoadRanges(t *testing.T) {
	r := &ElfReader{
		BaseAddr: 0x100000,
		Phdrs: []Elf64_Phdr{
			{Type: PT_LOAD, Vaddr: 0x2000, Offset: 0x2000, Memsz: 0x100},
		},
	}

	if got := r.normalizeLoadedAddressValue(0x102040); got != 0x2040 {
		t.Fatalf("in-range normalized value = 0x%x, want 0x2040", got)
	}
	if got := r.normalizeLoadedAddressValue(0x101000); got != 0x101000 {
		t.Fatalf("out-of-range normalized value = 0x%x, want 0x101000", got)
	}
}

func TestReadDynsRejectsMisalignedDynamicSize(t *testing.T) {
	r, _ := testReaderForBlob(t, make([]byte, 0x40))
	r.Phdrs = []Elf64_Phdr{{Type: PT_DYNAMIC, Vaddr: 0, Offset: 0, Memsz: uint64(sizeofDyn) + 1}}

	err := r.ReadDyns()
	if err == nil || !strings.Contains(err.Error(), "not a multiple") {
		t.Fatalf("expected dynamic size alignment error, got %v", err)
	}
}

func TestRelocationEntryCountRejectsTruncatedTables(t *testing.T) {
	_, err := relocationEntryCount("DT_REL", uint64(sizeofRel)+1, uint64(sizeofRel))
	if err == nil || !strings.Contains(err.Error(), "bad_size") {
		t.Fatalf("expected bad_size error, got %v", err)
	}
}

func TestReadArrayRejectsTruncatedTable(t *testing.T) {
	_, f := testReaderForBlob(t, make([]byte, sizeofRel-1))
	_, err := readArray[Elf64_Rel](f, 0, 1, "DT_REL")
	if err == nil || !strings.Contains(err.Error(), "truncated table") {
		t.Fatalf("expected truncated table error, got %v", err)
	}
}

func TestReadBoundedBlobRejectsTruncatedBlob(t *testing.T) {
	r, _ := testReaderForBlob(t, []byte("APS2"))
	_, err := r.readBoundedBlob(0, 5, "android_rel")
	if err == nil || !strings.Contains(err.Error(), "truncated_blob") {
		t.Fatalf("expected truncated_blob error, got %v", err)
	}
}

func TestPointerArrayCountRejectsMisalignedSize(t *testing.T) {
	_, err := pointerArrayCount("init_array", 9)
	if err == nil || !strings.Contains(err.Error(), "not pointer-aligned") {
		t.Fatalf("expected pointer alignment error, got %v", err)
	}
}

func TestReadElfMetadataReportsBadSymbolSectionSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-symbol-size.so")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	ehdr := Elf64_Ehdr{
		Magic:        [4]byte{0x7f, 'E', 'L', 'F'},
		Class:        ELFCLASS64,
		Data:         ELFDATA2LSB,
		IdentVersion: 1,
		Type:         ET_DYN,
		Machine:      EM_AARCH64,
		Version:      1,
		Ehsize:       sizeofEhdr,
		ShdrOffset:   sizeofEhdr,
		Shentsize:    sizeofShdr,
		Shnum:        2,
	}
	shdrs := []Elf64_Shdr{
		{},
		{
			Type:    SHT_DYNSYM,
			Offset:  uint64(sizeofEhdr + 2*sizeofShdr),
			Size:    uint64(sizeofSym + 1),
			Entsize: uint64(sizeofSym),
		},
	}
	if err := binary.Write(f, binary.LittleEndian, &ehdr); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, shdrs); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })

	_, issues := readElfMetadata(log.NewWithOptions(io.Discard, log.Options{}), in)
	if !containsIssue(issues, "symbols:bad_size") {
		t.Fatalf("expected symbols:bad_size issue, got %v", issues)
	}
}

func containsIssue(issues []string, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, want) {
			return true
		}
	}
	return false
}

func TestComputeRelaPREL64PreservesRuntimeSlot(t *testing.T) {
	const want = uint64(0xfeedfacecafebabe)
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, want)
	r := testRebuilderWithBytes(t, data)

	rela := Elf64_Rela{Offset: 0x4000, Info: uint64(R_AARCH64_PREL64), Addend: 0x1234}
	if got := r.computeRelaValue(&rela, 0); got != want {
		t.Fatalf("computeRelaValue(PREL64) = 0x%x, want 0x%x", got, want)
	}
}

func TestTLSRelocationsPreserveRuntimeSlot(t *testing.T) {
	for _, rt := range []RelocationType{R_AARCH64_TLS_DTPMOD, R_AARCH64_TLS_DTPREL, R_AARCH64_TLS_TPREL} {
		t.Run(rt.String(), func(t *testing.T) {
			const want = uint64(0x123456789abcdef0)
			data := make([]byte, 8)
			binary.LittleEndian.PutUint64(data, want)

			relRebuilder := testRebuilderWithBytes(t, data)
			rel := Elf64_Rel{Info: uint64(rt)}
			if got := relRebuilder.computeRelValue(&rel, 0); got != want {
				t.Fatalf("computeRelValue(%s) = 0x%x, want 0x%x", rt.String(), got, want)
			}

			relaRebuilder := testRebuilderWithBytes(t, data)
			rela := Elf64_Rela{Info: uint64(rt), Addend: 0x40}
			if got := relaRebuilder.computeRelaValue(&rela, 0); got != want {
				t.Fatalf("computeRelaValue(%s) = 0x%x, want 0x%x", rt.String(), got, want)
			}
		})
	}
}

func TestWriteRelocationTablesPersistsNormalizedMetadata(t *testing.T) {
	r := testRebuilderWithBytes(t, make([]byte, 0x100))
	r.BaseAddr = 0x1000
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Vaddr: 0, Offset: 0, Memsz: 0x100}}
	r.relVaddr = 0x20
	r.Rel = []Elf64_Rel{{Offset: 0x30, Info: uint64(R_AARCH64_RELATIVE)}}
	r.relrVaddr = 0x40
	r.Relr = []uint64{0x1038, 3}

	if err := r.writeRelocationTables(); err != nil {
		t.Fatal(err)
	}

	var rel Elf64_Rel
	if _, err := r.OutFile.Seek(0x20, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := binary.Read(r.OutFile, binary.LittleEndian, &rel); err != nil {
		t.Fatal(err)
	}
	if rel.Offset != 0x30 {
		t.Fatalf("written REL offset = 0x%x, want 0x30", rel.Offset)
	}

	var relr uint64
	if _, err := r.OutFile.Seek(0x40, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := binary.Read(r.OutFile, binary.LittleEndian, &relr); err != nil {
		t.Fatal(err)
	}
	if relr != 0x38 {
		t.Fatalf("written RELR entry = 0x%x, want 0x38", relr)
	}
}

func TestWriteSectionHeadersPreservesAndroidRelocationSectionTypes(t *testing.T) {
	r := testRebuilderWithBytes(t, make([]byte, 0x100))
	r.ElfHeader = &Elf64_Ehdr{PhdrOffset: 64, Phentsize: sizeofPhdr, Phnum: 1}
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Flags: PF_R, Vaddr: 0, Offset: 0, Filesz: 0x100, Memsz: 0x100}}
	r.androidRelVaddr = 0x20
	r.androidRelSize = 4
	r.androidRelaVaddr = 0x30
	r.androidRelaSize = 4
	r.relrVaddr = 0x40
	r.relrSize = 8
	r.relrSectionType = SHT_ANDROID_RELR

	if err := r.writeSectionHeaders(); err != nil {
		t.Fatal(err)
	}

	seen := map[string]SHT_Type{}
	for _, sec := range r.sections {
		seen[r.readSectionName(sec.Name)] = sec.Type
	}
	if seen[".android.rel.dyn"] != SHT_ANDROID_REL {
		t.Fatalf(".android.rel.dyn type = %s, want %s", seen[".android.rel.dyn"].String(), SHT_ANDROID_REL.String())
	}
	if seen[".android.rela.dyn"] != SHT_ANDROID_RELA {
		t.Fatalf(".android.rela.dyn type = %s, want %s", seen[".android.rela.dyn"].String(), SHT_ANDROID_RELA.String())
	}
	if seen[".relr.dyn"] != SHT_ANDROID_RELR {
		t.Fatalf(".relr.dyn type = %s, want %s", seen[".relr.dyn"].String(), SHT_ANDROID_RELR.String())
	}
}

func TestPatchResidualBasePointersSkipsReadOnlyLoadSegments(t *testing.T) {
	const want = uint64(0x1000)
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, want)

	r := testRebuilderWithBytes(t, data)
	r.BaseAddr = 0x1000
	r.TotalSize = 8
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Flags: PF_R, Vaddr: 0, Offset: 0, Filesz: 8, Memsz: 8}}

	if err := r.patchResidualBasePointers(); err != nil {
		t.Fatal(err)
	}

	got := r.readUint64OutAt(0)
	if got != want {
		t.Fatalf("read-only residual word was patched to 0x%x, want 0x%x", got, want)
	}
}

// TestIsDataRelocation exercises the real (unexported) isDataRelocation rather
// than a copy, so a change to the switch is actually caught.
func TestIsDataRelocation(t *testing.T) {
	tests := []struct {
		typ RelocationType
		ok  bool
	}{
		{R_AARCH64_NONE, false},
		{R_AARCH64_ABS64, true},
		{R_AARCH64_PREL64, true},
		{R_AARCH64_RELATIVE, true},
		{R_AARCH64_GLOB_DAT, true},
		{R_AARCH64_JUMP_SLOT, true},
		{R_AARCH64_COPY, true},
		{R_AARCH64_TLS_DTPMOD, true},
		{R_AARCH64_TLS_DTPREL, true},
		{R_AARCH64_TLS_TPREL, true},
		{R_AARCH64_TLSDESC, true},
		{R_AARCH64_IRELATIVE, true},
		{R_AARCH64_CALL26, false},
		{R_AARCH64_JUMP26, false},
		{R_AARCH64_ADR_PREL_PG_HI21, false},
		{RelocationType(0xDEAD), false},
	}
	for _, tt := range tests {
		if got := isDataRelocation(tt.typ); got != tt.ok {
			t.Errorf("isDataRelocation(%s)=%v, want %v", tt.typ.String(), got, tt.ok)
		}
	}
}

// TestCalculateSymbolCountFromHash covers the SysV .hash path: the count is the
// Nchain field of the hash header.
func TestCalculateSymbolCountFromHash(t *testing.T) {
	blob := make([]byte, 0x20)
	binary.LittleEndian.PutUint32(blob[0x10:], 3) // Nbucket
	binary.LittleEndian.PutUint32(blob[0x14:], 7) // Nchain
	r, _ := testReaderForBlob(t, blob)
	r.hashVaddr = 0x10
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Vaddr: 0, Offset: 0, Memsz: 0x100}}

	got, err := r.calculateSymbolCount()
	if err != nil {
		t.Fatal(err)
	}
	if got != 7 {
		t.Fatalf("calculateSymbolCount = %d, want 7 (Nchain)", got)
	}
}

// TestWriteFixedRelocsNormalizesRELR covers RELR anchor + bitmap expansion: each
// covered slot holding base+offset is normalized to a module-relative offset.
func TestWriteFixedRelocsNormalizesRELR(t *testing.T) {
	data := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(data[0x40:], 0x1040) // anchor slot: base(0x1000)+0x40
	binary.LittleEndian.PutUint64(data[0x48:], 0x1048) // bitmap slot: base+0x48
	r := testRebuilderWithBytes(t, data)
	r.BaseAddr = 0x1000
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Vaddr: 0, Offset: 0, Filesz: 0x100, Memsz: 0x100}}
	r.Relr = []uint64{0x40, 3} // even anchor 0x40, then bitmap bit 1 -> slot 0x48

	if err := r.writeFixedRelocs(); err != nil {
		t.Fatal(err)
	}
	if got := r.readUint64OutAt(0x40); got != 0x40 {
		t.Fatalf("RELR anchor slot = 0x%x, want 0x40", got)
	}
	if got := r.readUint64OutAt(0x48); got != 0x48 {
		t.Fatalf("RELR bitmap slot = 0x%x, want 0x48", got)
	}
}

// TestPatchResidualBasePointersRebasesWritableSlot is the positive counterpart to
// the read-only-skip test: a base+offset pointer in a writable segment that
// resolves back into the image is rebased.
func TestPatchResidualBasePointersRebasesWritableSlot(t *testing.T) {
	data := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(data[0x40:], 0x1040) // base(0x1000)+0x40, resolves into PT_LOAD
	r := testRebuilderWithBytes(t, data)
	r.BaseAddr = 0x1000
	r.TotalSize = 0x100
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Flags: PF_R | PF_W, Vaddr: 0, Offset: 0, Filesz: 0x100, Memsz: 0x100}}

	if err := r.patchResidualBasePointers(); err != nil {
		t.Fatal(err)
	}
	if got := r.readUint64OutAt(0x40); got != 0x40 {
		t.Fatalf("writable residual slot = 0x%x, want 0x40 (rebased)", got)
	}
}

// TestDecodePackedRelaAPS2NonGrouped covers the non-grouped APS2 branch, where
// each entry carries its own offset delta and info (no group-level fields).
func TestDecodePackedRelaAPS2NonGrouped(t *testing.T) {
	blob := []byte("APS2")
	for _, v := range []int64{
		2, 0x1000, // reloc_count, initial_offset
		2, 0, // group_size, group_flags (ungrouped, no addend)
		8, int64(R_AARCH64_RELATIVE), // entry0: offset_delta, info
		8, int64(R_AARCH64_RELATIVE), // entry1: offset_delta, info
	} {
		blob = appendTestSLEB(blob, v)
	}

	r, _ := testReaderForBlob(t, blob)
	got, err := r.decodePackedRela(0, uint64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	wantOffsets := []uint64{0x1008, 0x1010}
	if len(got) != len(wantOffsets) {
		t.Fatalf("decoded %d relocs, want %d", len(got), len(wantOffsets))
	}
	for i, want := range wantOffsets {
		if got[i].Offset != want || got[i].Addend != 0 || got[i].Type() != R_AARCH64_RELATIVE {
			t.Fatalf("reloc[%d] = {off=0x%x add=%d type=%s}, want {off=0x%x add=0 type=RELATIVE}",
				i, got[i].Offset, got[i].Addend, got[i].Type().String(), want)
		}
	}
}

// TestDecodePackedRelaAPA1 covers the APA1 RELA format: cumulative
// (offset_delta, addend_delta) pairs, all R_AARCH64_RELATIVE.
func TestDecodePackedRelaAPA1(t *testing.T) {
	blob := []byte("APA1")
	for _, v := range []int64{
		2,           // pairs
		0x100, 0x10, // pair 0: offset_delta, addend_delta
		0x8, 0x20, // pair 1
	} {
		blob = appendTestSLEB(blob, v)
	}
	r, _ := testReaderForBlob(t, blob)
	got, err := r.decodePackedRela(0, uint64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	want := []Elf64_Rela{
		{Offset: 0x100, Info: uint64(R_AARCH64_RELATIVE), Addend: 0x10},
		{Offset: 0x108, Info: uint64(R_AARCH64_RELATIVE), Addend: 0x30},
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d relocs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reloc[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestDecodePackedRelAPR1 covers the APR1 REL format: an initial offset plus
// run-length (count, delta) pairs, all R_AARCH64_RELATIVE.
func TestDecodePackedRelAPR1(t *testing.T) {
	blob := []byte("APR1")
	for _, v := range []int64{
		1,      // pairs
		0x1000, // initial_offset
		2, 8,   // pair: count, delta
	} {
		blob = appendTestSLEB(blob, v)
	}
	r, _ := testReaderForBlob(t, blob)
	got, err := r.decodePackedRel(0, uint64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	wantOffsets := []uint64{0x1000, 0x1008, 0x1010}
	if len(got) != len(wantOffsets) {
		t.Fatalf("decoded %d relocs, want %d", len(got), len(wantOffsets))
	}
	for i, off := range wantOffsets {
		if got[i].Offset != off || got[i].Type() != R_AARCH64_RELATIVE {
			t.Fatalf("rel[%d] = {off=0x%x type=%s}, want off=0x%x RELATIVE",
				i, got[i].Offset, got[i].Type().String(), off)
		}
	}
}

// TestWriteFixedRelocsTLSDESCSecondSlot drives the full writeFixedRelocs path
// for an R_AARCH64_TLSDESC entry and asserts both descriptor words (the resolver
// pointer and its argument at +8) are normalized.
func TestWriteFixedRelocsTLSDESCSecondSlot(t *testing.T) {
	data := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(data[0x40:], 0x1040) // first word: base(0x1000)+0x40
	binary.LittleEndian.PutUint64(data[0x48:], 0x1048) // second word: base+0x48
	r := testRebuilderWithBytes(t, data)
	r.BaseAddr = 0x1000
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Vaddr: 0, Offset: 0, Filesz: 0x100, Memsz: 0x100}}
	r.Rela = []Elf64_Rela{{Offset: 0x40, Info: uint64(R_AARCH64_TLSDESC)}}

	if err := r.writeFixedRelocs(); err != nil {
		t.Fatal(err)
	}
	if got := r.readUint64OutAt(0x40); got != 0x40 {
		t.Fatalf("TLSDESC first word = 0x%x, want 0x40", got)
	}
	if got := r.readUint64OutAt(0x48); got != 0x48 {
		t.Fatalf("TLSDESC second word = 0x%x, want 0x48", got)
	}
}

// TestResolveAddress covers the checker's symbol > section > segment resolution.
func TestResolveAddress(t *testing.T) {
	meta := &elfMetadata{
		symbols:  []resolvedSymbol{{name: "foo", value: 0x2000, size: 0x40}},
		shdrs:    []Elf64_Shdr{{}, {Addr: 0x3000, Size: 0x100, Name: 1}},
		shstrtab: []byte{0, '.', 't', 'e', 'x', 't', 0},
		phdrs:    []Elf64_Phdr{{Type: PT_LOAD, Flags: PF_R | PF_X, Vaddr: 0x1000, Memsz: 0x2000}},
	}
	cases := []struct {
		addr uint64
		want string
	}{
		{0x2000, "sym.foo"},               // exact symbol
		{0x2010, "sym.foo+0x10"},          // inside symbol
		{0x3050, "section[1]..text+0x50"}, // inside section (name is ".text")
		{0x1500, "RX@0x1000+0x500"},       // segment fallback
		{0x9999, ""},                      // nothing
	}
	for _, c := range cases {
		if got := resolveAddress(meta, c.addr); got != c.want {
			t.Errorf("resolveAddress(0x%x) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// TestNormalizeRelOffsets covers the REL-table offset normalizer (the sample
// corpus is RELA-only, so this path is otherwise unexercised).
func TestNormalizeRelOffsets(t *testing.T) {
	r := &ElfReader{
		BaseAddr: 0x1000,
		Phdrs:    []Elf64_Phdr{{Type: PT_LOAD, Vaddr: 0, Offset: 0, Memsz: 0x100}},
	}
	list := []Elf64_Rel{{Offset: 0x1040}, {Offset: 0x40}}
	r.normalizeRelOffsets(list)
	if list[0].Offset != 0x40 {
		t.Fatalf("rel[0].Offset = 0x%x, want 0x40 (normalized)", list[0].Offset)
	}
	if list[1].Offset != 0x40 {
		t.Fatalf("rel[1].Offset = 0x%x, want 0x40 (out of range, unchanged)", list[1].Offset)
	}
}

// TestEnumStringers covers every enum String() method, including the default
// (unknown value) branch of each.
func TestEnumStringers(t *testing.T) {
	cases := []struct{ got, want string }{
		{PF_Flags(0).String(), "0"},
		{(PF_R | PF_W | PF_X).String(), "PF_R|PF_W|PF_X"},
		{SHT_PROGBITS.String(), "SHT_PROGBITS"},
		{SHT_Type(0x12345678).String(), "SHT_UNKNOWN(0x12345678)"},
		{PT_LOAD.String(), "PT_LOAD"},
		{PT_Type(0x99).String(), "UNKNOWN_PT_TYPE(0x99)"},
		{DT_NULL.String(), "DT_NULL"},
		{DT_Tag(0x12345).String(), "DT_UNKNOWN(0x12345)"},
		{R_AARCH64_RELATIVE.String(), "R_AARCH64_RELATIVE"},
		{RelocationType(0xffff).String(), "UNKNOWN_RELOC_TYPE(65535)"},
		{STB_GLOBAL.String(), "STB_GLOBAL"},
		{SymbolBinding(9).String(), "STB_UNKNOWN_BINDING(9)"},
		{STT_FUNC.String(), "STT_FUNC"},
		{SymbolType(9).String(), "STT_UNKNOWN(9)"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Errorf("stringer case %d: got %q, want %q", i, c.got, c.want)
		}
	}
}

// TestWriteFixedRelocsRELPath exercises applyRelRelocs and the REL branch of
// computeRelValue (AArch64 samples are RELA-only, so this path is otherwise
// unexercised end to end).
func TestWriteFixedRelocsRELPath(t *testing.T) {
	data := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(data[0x40:], 0x1040) // RELATIVE slot: base+0x40
	binary.LittleEndian.PutUint64(data[0x50:], 0x1050) // GLOB_DAT slot: base+0x50
	r := testRebuilderWithBytes(t, data)
	r.BaseAddr = 0x1000
	r.Phdrs = []Elf64_Phdr{{Type: PT_LOAD, Vaddr: 0, Offset: 0, Filesz: 0x100, Memsz: 0x100}}
	r.Rel = []Elf64_Rel{
		{Offset: 0x40, Info: uint64(R_AARCH64_RELATIVE)},
		{Offset: 0x50, Info: uint64(R_AARCH64_GLOB_DAT)},
	}
	if err := r.writeFixedRelocs(); err != nil {
		t.Fatal(err)
	}
	if got := r.readUint64OutAt(0x40); got != 0x40 {
		t.Fatalf("REL RELATIVE slot = 0x%x, want 0x40", got)
	}
	if got := r.readUint64OutAt(0x50); got != 0x50 {
		t.Fatalf("REL GLOB_DAT slot = 0x%x, want 0x50", got)
	}
}
