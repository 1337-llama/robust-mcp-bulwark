// LAB ONLY: source checks that keep the attack lab harmless and deterministic.
package lab_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var banned = map[string]string{
	"net": "AC-4", "net/http": "AC-4", "net/rpc": "AC-4",
	"math/rand": "AC-9", "math/rand/v2": "AC-9", "crypto/rand": "AC-9",
}

// Verifies: FR-002, FR-008 (AC-4 no direct networking imports; AC-9 no clock or
// randomness; CLAUDE.md hard rule 4: every lab file carries a LAB ONLY banner)
func TestLabSourceScan(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(src), "// LAB ONLY") {
			t.Errorf("%s: missing LAB ONLY banner", path)
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(string(src), "time.Now(") {
			t.Errorf("%s: uses time.Now (AC-9)", path)
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); banned[p] != "" {
				t.Errorf("%s imports %s (%s)", path, p, banned[p])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
