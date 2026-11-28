package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeChain(t *testing.T, n int) (string, *Writer) {
	dir := t.TempDir()
	w, err := Open(filepath.Join(dir, "audit", "fs"), filepath.Join(dir, "audit.key"), func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := w.Write(Record{Event: "call_decision", Method: "tools/call", Detail: map[string]any{"n": 1e21, "i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "audit", "fs", "*.jsonl"))
	return files[0], w
}

// Verifies: FR-026, NFR-006 (AC-20, AC-21 chain and key; AC-22 tamper detection)
func TestChainAndTamper(t *testing.T) {
	path, w := writeChain(t, 4)
	b, _ := os.ReadFile(path)
	if n, err := Verify(bytes.NewReader(b)); err != nil || n != 4 {
		t.Fatalf("intact chain: %d, %v", n, err)
	}
	if fi, _ := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "audit.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", fi.Mode().Perm())
	}
	lines := strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	tamper := map[string]string{
		"modify":  strings.Replace(string(b), `"i":1`, `"i":9`, 1),
		"delete":  lines[0] + lines[2] + lines[3],
		"reorder": lines[0] + lines[2] + lines[1] + lines[3],
		"insert":  lines[0] + lines[1] + lines[1] + lines[2] + lines[3],
	}
	for name, s := range tamper {
		var broken *ErrBroken
		if _, err := Verify(strings.NewReader(s)); !errors.As(err, &broken) {
			t.Errorf("%s not detected: %v", name, err)
		}
	}
	// Truncating the tail is the documented limit (AR-6): it still verifies.
	if _, err := Verify(strings.NewReader(lines[0] + lines[1])); err != nil {
		t.Errorf("truncated prefix: %v", err)
	}
	x1, x2, y := w.MAC([]byte("x")), w.MAC([]byte("x")), w.MAC([]byte("y"))
	if !strings.HasPrefix(x1, "hmac-sha256:") || x1 != x2 || x1 == y {
		t.Error("args MAC must be stable and keyed")
	}
}

// Two processes starting at once on a fresh install get the same key.
func TestKeyRace(t *testing.T) {
	dir := t.TempDir()
	keys := make(chan []byte, 8)
	for i := 0; i < 8; i++ {
		go func() {
			k, err := loadKey(filepath.Join(dir, "audit.key"))
			if err != nil {
				t.Error(err)
			}
			keys <- k
		}()
	}
	first := <-keys
	for i := 1; i < 8; i++ {
		if k := <-keys; !bytes.Equal(k, first) {
			t.Fatal("processes saw different keys")
		}
	}
}
