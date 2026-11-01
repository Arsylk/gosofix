package sofixer

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A subprocess exercises the real stdout pipe and isolates the logger's cached
// renderer between environment configurations.
func TestLoggerColorProfile(t *testing.T) {
	if os.Getenv("GOSOFIX_COLOR_TEST") == "1" {
		lg, err := newLogger(1)
		if err != nil {
			t.Fatal(err)
		}
		lg.Info("elf fix", "path", "libtest.bin", "base", uint64(0x1000), "count", 2)
		return
	}
	for _, tc := range []struct {
		name    string
		force   string
		noColor *string
		color   bool
	}{
		{name: "forced truecolor", force: "1", color: true},
		{name: "forced nonzero", force: "yes", color: true},
		{name: "force disabled", force: "0"},
		{name: "normal pipe"},
		{name: "no color wins", force: "1", noColor: colorTestString("1")},
		{name: "empty no color wins", force: "1", noColor: colorTestString("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoggerColorProfile$")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "CLICOLOR_FORCE=") && !strings.HasPrefix(entry, "NO_COLOR=") && !strings.HasPrefix(entry, "GOSOFIX_COLOR_TEST=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "GOSOFIX_COLOR_TEST=1", "CLICOLOR_FORCE="+tc.force)
			if tc.noColor != nil {
				cmd.Env = append(cmd.Env, "NO_COLOR="+*tc.noColor)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("logger subprocess: %v\n%s", err, out)
			}
			s := string(out)
			if !strings.Contains(s, "elf fix") || !strings.Contains(s, "libtest.bin") {
				t.Fatalf("missing log output: %q", s)
			}
			if tc.color {
				for _, rgb := range []string{"116;199;236", "108;112;134", "249;226;175", "250;179;135", "203;166;247"} {
					if !strings.Contains(s, "38;2;"+rgb+"m") {
						t.Errorf("missing native RGB color %s in %q", rgb, s)
					}
				}
			} else if strings.Contains(s, "\x1b") {
				t.Errorf("unexpected colors: %q", s)
			}
		})
	}
}

func colorTestString(s string) *string { return &s }
