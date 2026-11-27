package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root string, files map[string]string) {
	for name, body := range files {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const sha40 = "3d3c42e5aac5ba805825da76410c181273ba90b1"

// Verifies: NFR-001 (AC-25 runner labels and SHA pins; AC-23 timeouts)
func TestLabels(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{".github/workflows/ci.yml": `on: [pull_request]
jobs:
  good:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@` + sha40 + `
      - uses: ./local-action
  big:
    runs-on: ubuntu-latest-16-cores
    timeout-minutes: 10
    steps: [{uses: actions/checkout@v7}]
  slow:
    runs-on: ubuntu-24.04
    steps: [{uses: some/action@main}]
`})
	got := strings.Join(labels(root), "\n")
	for _, want := range []string{"job big: runner ubuntu-latest-16-cores", "job big: actions/checkout@v7 is not pinned", "job slow: PR jobs must set timeout-minutes: 10", "job slow: some/action@main is not pinned"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "job good") {
		t.Errorf("good job flagged:\n%s", got)
	}
}

// Verifies: NFR-002 (AC-26 coverage; AC-29 pending)
func TestCoverageAndPending(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"specs/001-a/spec.md":     "| Status | Done |\n| Traces to | FR-001, FR-002, NFR-003 |\n",
		"specs/002-b/spec.md":     "| Status | Ready |\n| Traces to | FR-009 |\n",
		"x/a_test.go":             "// Verifies: FR-001\nfunc TestNFR003Thing(t *testing.T) {}\n",
		"lab/scenarios/L-01.yaml": "runs:\n  - pending: spec-001\n  - pending: spec-002\n",
	})
	if got := coverage(root); len(got) != 1 || !strings.Contains(got[0], "FR-002") {
		t.Errorf("coverage: %v", got)
	}
	if got := pending(root); len(got) != 1 || !strings.Contains(got[0], "spec 001") {
		t.Errorf("pending: %v", got)
	}
}

func TestRepoPasses(t *testing.T) {
	for name, check := range map[string]func(string) []string{"labels": labels, "coverage": coverage, "pending": pending} {
		if got := check("../.."); len(got) > 0 {
			t.Errorf("%s on this repo: %v", name, got)
		}
	}
}
