package main

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Verifies: NFR-007, NFR-014 (spec 002 AC-32: the gateway's own packages never import net, net/http or net/rpc)
func TestNoNetworkImports(t *testing.T) {
	for _, root := range []string{"../../cmd", "../../internal"} {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				switch path, _ := strconv.Unquote(imp.Path.Value); path {
				case "net", "net/http", "net/rpc":
					t.Errorf("%s imports %s", p, path)
				}
			}
			return nil
		})
	}
}
