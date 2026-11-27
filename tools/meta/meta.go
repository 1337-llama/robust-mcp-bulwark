// Command meta runs repository checks in CI (spec 001 AC-23, AC-25, AC-26, AC-29):
//
//	meta labels   workflows use standard runners, SHA-pinned actions, 10-minute timeouts
//	meta coverage every requirement traced by a Done spec is named by a test
//	meta pending  no manifest still waits on a Done spec
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: meta labels|coverage|pending")
		os.Exit(2)
	}
	checks := map[string]func(string) []string{"labels": labels, "coverage": coverage, "pending": pending}
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

var sha = regexp.MustCompile(`@[0-9a-f]{40}$`)

func labels(root string) []string {
	files, _ := filepath.Glob(filepath.Join(root, ".github/workflows/*.y*ml"))
	var out []string
	for _, f := range files {
		var wf struct {
			Jobs map[string]struct {
				RunsOn  any `yaml:"runs-on"`
				Timeout any `yaml:"timeout-minutes"`
				Uses    string
				Steps   []struct{ Uses string }
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
			if r, ok := j.RunsOn.(string); j.Uses == "" && (!ok || !allowedRunners[r]) {
				out = append(out, fmt.Sprintf("%s: runner %v is not a standard GitHub-hosted label", where, j.RunsOn))
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

func coverage(root string) []string {
	var tests strings.Builder
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, "_test.go") {
			b, _ := os.ReadFile(p)
			tests.Write(b)
		}
		return nil
	})
	src := tests.String()
	var out []string
	for spec, ids := range doneSpecs(root) {
		for _, id := range ids {
			named := strings.Contains(src, "func Test"+strings.ReplaceAll(id, "-", "")) // e.g. TestFR001Parse
			if !named && !regexp.MustCompile(`// Verifies:.*\b`+id+`\b`).MatchString(src) {
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
		for _, m := range regexp.MustCompile(`pending:\s*spec-(\d{3})`).FindAllStringSubmatch(string(b), -1) {
			if _, ok := done[m[1]]; ok {
				out = append(out, fmt.Sprintf("%s: still pending on spec %s, which is Done", f, m[1]))
			}
		}
	}
	sort.Strings(out)
	return out
}
