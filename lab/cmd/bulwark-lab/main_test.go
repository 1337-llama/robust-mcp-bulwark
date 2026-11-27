// LAB ONLY: tests for the lab binary guard.
package main

import (
	"bytes"
	"strings"
	"testing"
)

// failReader fails the test if the guard reads stdin before deciding (AC-5).
type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) { r.t.Fatal("read stdin"); return 0, nil }

// Verifies: FR-008 (AC-5 guard, AC-6 banner)
func TestGuardAndBanner(t *testing.T) {
	cases := []struct {
		env, arg string
		code     int
		stderr   string
	}{
		{"", "l01-notes", 2, "BULWARK_LAB=1"},
		{"0", "l01-notes", 2, "BULWARK_LAB=1"},
		{"1", "", 2, "usage"},
		{"1", "nope", 2, "unknown lab server"},
	}
	for _, c := range cases {
		var out bytes.Buffer
		args := []string{}
		if c.arg != "" {
			args = append(args, c.arg)
		}
		code := run(args, func(string) string { return c.env }, failReader{t}, &out, &out)
		if code != c.code || !strings.Contains(out.String(), c.stderr) {
			t.Errorf("env=%q arg=%q: code %d, stderr %q", c.env, c.arg, code, out.String())
		}
		if c.env == "1" && !strings.HasPrefix(out.String(), "LAB ONLY") {
			t.Errorf("banner missing: %q", out.String())
		}
	}
}
