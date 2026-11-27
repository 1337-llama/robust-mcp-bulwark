// LAB ONLY: source checks that keep the attack lab harmless and deterministic.
package lab_test

import (
	"go/ast"
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
	"net": "AC-4", "net/http": "AC-4", "net/rpc": "AC-4", "os/exec": "AC-4", "syscall": "AC-4",
	"math/rand": "AC-9", "math/rand/v2": "AC-9", "crypto/rand": "AC-9",
}

var clockFuncs = map[string]bool{"Now": true, "Since": true, "Until": true, "Tick": true, "After": true, "AfterFunc": true, "NewTimer": true, "NewTicker": true}

// scan returns the problems in one lab Go file.
func scan(path string, src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ParseComments)
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	banner := false
	for _, c := range f.Comments {
		banner = banner || (c.Pos() < f.Package && strings.Contains(c.Text(), "LAB ONLY"))
	}
	if !banner {
		out = append(out, path+": missing LAB ONLY banner")
	}
	if strings.HasSuffix(path, "_test.go") {
		return out
	}
	timeName := ""
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if banned[p] != "" {
			out = append(out, path+" imports "+p+" ("+banned[p]+")")
		}
		if p == "time" {
			timeName = "time"
			if imp.Name != nil {
				timeName = imp.Name.Name
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && timeName != "" && clockFuncs[s.Sel.Name] {
			if id, ok := s.X.(*ast.Ident); ok && id.Name == timeName {
				out = append(out, path+": reads the clock with time."+s.Sel.Name+" (AC-9)")
			}
		}
		return true
	})
	return out
}

// Verifies: FR-002, FR-008 (AC-4 no direct networking or process spawning; AC-9 no
// clock or randomness; CLAUDE.md hard rule 4: every lab file carries a LAB ONLY banner)
func TestLabSourceScan(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		src, err := os.ReadFile(path)
		for _, p := range scan(path, src) {
			t.Error(p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanCatches(t *testing.T) {
	bad := "// LAB ONLY\npackage x\n\nimport (\n\tclock \"time\"\n\t_ \"net\"\n)\n\nvar _ = clock.Since\n"
	got := strings.Join(scan("x.go", []byte(bad)), "\n")
	for _, want := range []string{"imports net", "time.Since"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if got := scan("y.go", []byte("//go:build linux\n\n// LAB ONLY: x\npackage x\n")); len(got) != 0 {
		t.Errorf("banner after build tag rejected: %v", got)
	}
	if got := scan("z.go", []byte("package x\n")); len(got) != 1 {
		t.Errorf("missing banner not caught: %v", got)
	}
}
