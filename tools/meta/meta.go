// Command meta runs repository checks in CI (spec 001 AC-23, AC-25, AC-26, AC-29):
//
//	meta labels   workflows use standard runners, SHA-pinned actions, 10-minute timeouts
//	meta coverage every requirement traced by a Done spec is named by a test
//	meta pending  no manifest still waits on a Done spec
//	meta trace F  the strace output F has no AF_INET/AF_INET6 socket (AC-21)
//	meta hidden   no tracked text file contains a Cc/Cf/Zl/Zp character (spec 002 AC-34)
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "trace" {
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if bad := inetSockets(string(b)); len(bad) > 0 {
			fmt.Println(strings.Join(bad, "\n"))
			os.Exit(3)
		}
		return
	}
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: meta labels|coverage|pending | meta trace FILE")
		os.Exit(2)
	}
	checks := map[string]func(string) []string{"labels": labels, "coverage": coverage, "pending": pending, "hidden": hidden}
	check, ok := checks[os.Args[1]]
	if !ok {
		fmt.Fprintln(os.Stderr, "meta: unknown check", os.Args[1])
		os.Exit(2)
	}
	problems := check(".")
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		os.Exit(3)
	}
}

// Standard GitHub-hosted labels only: larger runners cost money (DESIGN.md C-4).
var allowedRunners = map[string]bool{
	"ubuntu-latest": true, "ubuntu-24.04": true, "ubuntu-22.04": true,
	"ubuntu-24.04-arm": true, "macos-latest": true, "macos-15": true, "macos-14": true,
	"windows-latest": true, "windows-2025": true, "windows-2022": true,
}

var (
	sha        = regexp.MustCompile(`@[0-9a-f]{40}$|^docker://[^@]+@sha256:[0-9a-f]{64}$`)
	matrixRef  = regexp.MustCompile(`^\$\{\{\s*matrix\.(\w+)\s*\}\}$`)
	pendingRef = regexp.MustCompile(`pending:\s*spec-(\d{3})`)
)

func labels(root string) []string {
	files, _ := filepath.Glob(filepath.Join(root, ".github/workflows/*.y*ml"))
	var out []string
	for _, f := range files {
		var wf struct {
			Jobs map[string]struct {
				RunsOn   any `yaml:"runs-on"`
				Timeout  any `yaml:"timeout-minutes"`
				Strategy struct{ Matrix map[string]any }
				Uses     string
				Steps    []struct{ Uses string }
			}
		}
		b, err := os.ReadFile(f)
		if err == nil {
			err = yaml.Unmarshal(b, &wf)
		}
		if err != nil {
			out = append(out, fmt.Sprintf("%s: %v", f, err))
			continue
		}
		pr := strings.Contains(string(b), "pull_request")
		for name, j := range wf.Jobs {
			where := fmt.Sprintf("%s: job %s", f, name)
			runners := []any{j.RunsOn}
			if r, ok := j.RunsOn.(string); ok {
				if m := matrixRef.FindStringSubmatch(r); m != nil {
					runners, _ = j.Strategy.Matrix[m[1]].([]any) // every matrix value must be allowed
				}
			}
			for _, r := range runners {
				if name, ok := r.(string); j.Uses == "" && (!ok || !allowedRunners[name]) {
					out = append(out, fmt.Sprintf("%s: runner %v is not a standard GitHub-hosted label", where, r))
				}
			}
			if len(runners) == 0 && j.Uses == "" {
				out = append(out, where+": runner matrix is empty or not a list")
			}
			if pr && j.Uses == "" && j.Timeout != 10 {
				out = append(out, where+": PR jobs must set timeout-minutes: 10")
			}
			uses := []string{j.Uses}
			for _, s := range j.Steps {
				uses = append(uses, s.Uses)
			}
			for _, u := range uses {
				if u != "" && !strings.HasPrefix(u, "./") && !sha.MatchString(u) {
					out = append(out, fmt.Sprintf("%s: %s is not pinned to a full commit SHA", where, u))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

var (
	statusDone = regexp.MustCompile(`(?m)^\| Status \| Done`)
	tracesRow  = regexp.MustCompile(`(?m)^\| Traces to \|(.*)\|`)
	reqID      = regexp.MustCompile(`\bN?FR-\d{3}\b`)
)

// doneSpecs returns spec number → traced requirement IDs for every Done spec.
func doneSpecs(root string) map[string][]string {
	specs, _ := filepath.Glob(filepath.Join(root, "specs/*/spec.md"))
	done := map[string][]string{}
	for _, f := range specs {
		b, _ := os.ReadFile(f)
		if !statusDone.Match(b) {
			continue
		}
		var ids []string
		if m := tracesRow.FindSubmatch(b); m != nil {
			ids = reqID.FindAllString(string(m[1]), -1)
		}
		done[filepath.Base(filepath.Dir(f))[:3]] = ids
	}
	return done
}

var testName = regexp.MustCompile(`^Test(N?FR)(\d{3})`)

// covered collects the requirement IDs named by test functions (TestFR001…) or
// by "// Verifies:" comments in _test.go files. Files are parsed, so string
// literals and fixtures never count.
func covered(root string) map[string]bool {
	ids := map[string]bool{}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ParseComments)
		if err != nil {
			return nil
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				if m := testName.FindStringSubmatch(fn.Name.Name); m != nil {
					ids[m[1]+"-"+m[2]] = true
				}
			}
		}
		for _, c := range f.Comments {
			if t := c.Text(); strings.Contains(t, "Verifies:") {
				for _, id := range reqID.FindAllString(t, -1) {
					ids[id] = true
				}
			}
		}
		return nil
	})
	return ids
}

func coverage(root string) []string {
	have := covered(root)
	var out []string
	for spec, ids := range doneSpecs(root) {
		for _, id := range ids {
			if !have[id] {
				out = append(out, fmt.Sprintf("spec %s is Done but %s has no test (name or // Verifies:)", spec, id))
			}
		}
	}
	sort.Strings(out)
	return out
}

func pending(root string) []string {
	done := doneSpecs(root)
	files, _ := filepath.Glob(filepath.Join(root, "lab/scenarios/L-*.yaml"))
	var out []string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, m := range pendingRef.FindAllStringSubmatch(string(b), -1) {
			if _, ok := done[m[1]]; ok {
				out = append(out, fmt.Sprintf("%s: still pending on spec %s, which is Done", f, m[1]))
			}
		}
	}
	sort.Strings(out)
	return out
}

var (
	inetSocket  = regexp.MustCompile(`\bsocket(pair)?\((AF|PF)_INET6?\b`)
	labExec     = regexp.MustCompile(`\bexecve\("[^"]*bulwark-lab"`)
	gatewayExec = regexp.MustCompile(`\bexecve\("[^"]*/bulwark"`)
)

// inetSockets returns every strace line that creates an internet socket, from
// any process (strace -f prefixes lines with the PID). AF_UNIX is allowed. A
// trace with no execve of bulwark-lab proves nothing, so it fails too.
func inetSockets(trace string) []string {
	var bad []string
	if !labExec.MatchString(trace) {
		bad = append(bad, "trace shows no execve of bulwark-lab: the lab servers did not run under strace")
	}
	if !gatewayExec.MatchString(trace) { // spec 002 AC-32: the gateway itself is traced too
		bad = append(bad, "trace shows no execve of bulwark: the gateway did not run under strace")
	}
	for _, line := range strings.Split(trace, "\n") {
		if inetSocket.MatchString(line) {
			bad = append(bad, line)
		}
	}
	return bad
}

// hidden lists tracked text files containing invisible or control characters
// (tab, newline and carriage return are allowed). Binary files are skipped.
func hidden(root string) []string {
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		return []string{"git ls-files: " + err.Error()}
	}
	var bad []string
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || bytes.IndexByte(b, 0) >= 0 {
			continue // binary (contains NUL); invalid UTF-8 elsewhere is still scanned
		}
		if n := hiddenRunes(string(b)); n > 0 {
			bad = append(bad, fmt.Sprintf("%s: %d hidden or control characters", name, n))
		}
	}
	return bad
}

func hiddenRunes(s string) int {
	n := 0
	for _, r := range s {
		if r != '\t' && r != '\n' && r != '\r' && unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			n++
		}
	}
	return n
}
