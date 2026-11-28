package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verifies: FR-021 (AC-29 permissions and enforce refusal; AC-30 server id; command digest)
func TestState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if w, err := Prepare(dir, "enforce"); err != nil || len(w) != 0 {
		t.Fatalf("fresh dir: %v %v", w, err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	os.WriteFile(filepath.Join(dir, "pins.json"), nil, 0o600)
	os.Chmod(filepath.Join(dir, "pins.json"), 0o666)
	if w, err := Prepare(dir, "warn"); err != nil || len(w) != 1 {
		t.Errorf("warn mode should only warn: %v %v", w, err)
	}
	if _, err := Prepare(dir, "enforce"); err == nil {
		t.Error("enforce must refuse a world-writable file")
	}

	real := filepath.Join(t.TempDir(), "real")
	os.MkdirAll(real, 0o700)
	os.WriteFile(filepath.Join(real, "f"), nil, 0o600)
	os.Chmod(filepath.Join(real, "f"), 0o666)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(real, link)
	if _, err := Prepare(link, "enforce"); err == nil {
		t.Error("a symlinked state_dir must be inspected through the link")
	}

	a, err := CommandDigest([]string{"sh", "-c", "true"})
	b, _ := CommandDigest([]string{"sh", "-c", "false"})
	if err != nil || !strings.HasPrefix(a, "sha256:") || a == b {
		t.Fatalf("digest %q %q %v", a, b, err)
	}
	if id, _ := ServerID("", "warn", a); id != "auto-"+a[7:19] {
		t.Errorf("default id %q", id)
	}
	if _, err := ServerID("", "enforce", a); err == nil {
		t.Error("enforce needs --server-id")
	}
}
