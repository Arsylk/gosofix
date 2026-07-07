package main

import (
	"strings"
	"testing"
)

func TestAutoparseMemAddr(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"libfoo.so_dump_0x7abc123000.so", 0x7abc123000, false},
		{"0x1000", 0x1000, false},
		{"/path/to/saitcza.so_dump_0x76c8436000.so", 0x76c8436000, false},
		{"no-hex-here.so", 0, true},
		{"", 0, true},
		{"deadbeef", 0, true}, // missing 0x prefix must not be grabbed
	}
	for _, c := range cases {
		got, err := autoparseMemAddr(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("autoparseMemAddr(%q) = 0x%x, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("autoparseMemAddr(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("autoparseMemAddr(%q) = 0x%x, want 0x%x", c.in, got, c.want)
		}
	}
}

func TestAutogenerateOutputPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"dump.so", "dump_fix.so"},
		{"/path/to/lib.so", "/path/to/lib_fix.so"},
		{"noext", "noext_fix"},
	}
	for _, c := range cases {
		if got := autogenerateOutputPath(c.in); got != c.want {
			t.Errorf("autogenerateOutputPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFixElfErrorPaths(t *testing.T) {
	if _, err := fixElf("", 0x1000, "out.so", 0); err == nil || !strings.Contains(err.Error(), "missing input") {
		t.Errorf("empty input: expected missing-input error, got %v", err)
	}
	// memAddr 0 with a filename carrying no 0x-address must fail base detection.
	if _, err := fixElf("plainname.so", 0, "out.so", 0); err == nil || !strings.Contains(err.Error(), "incorrect memory addr") {
		t.Errorf("no-addr filename: expected incorrect-memory-addr error, got %v", err)
	}
}
