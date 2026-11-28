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
      - uses: docker://alpine@sha256:` + strings.Repeat("a", 64) + `
  matrix:
    strategy: {matrix: {os: [ubuntu-24.04, macos-15]}}
    runs-on: ${{ matrix.os }}
    timeout-minutes: 10
  badmatrix:
    strategy: {matrix: {os: [ubuntu-24.04, self-hosted]}}
    runs-on: ${{ matrix.os }}
    timeout-minutes: 10
  big:
    runs-on: ubuntu-latest-16-cores
    timeout-minutes: 10
    steps: [{uses: actions/checkout@v7}]
  slow:
    runs-on: ubuntu-24.04
    steps: [{uses: some/action@main}]
`})
	got := strings.Join(labels(root), "\n")
	for _, want := range []string{"job big: runner ubuntu-latest-16-cores", "job big: actions/checkout@v7 is not pinned", "job slow: PR jobs must set timeout-minutes: 10", "job slow: some/action@main is not pinned", "job badmatrix: runner self-hosted"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "job good") || strings.Contains(got, "job matrix:") {
		t.Errorf("good job flagged:\n%s", got)
	}
}

// Verifies: NFR-002 (AC-26 coverage; AC-29 pending)
func TestCoverageAndPending(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"specs/001-a/spec.md":     "| Status | Done |\n| Traces to | FR-001, FR-002, NFR-003 |\n",
		"specs/002-b/spec.md":     "| Status | Ready |\n| Traces to | FR-009 |\n",
		"x/a_test.go":             "package x\n\nimport \"testing\"\n\n// Verifies: FR-001\nfunc TestNFR003Thing(t *testing.T) {}\n\nvar s = \"// Verifies: FR-002\"\n",
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
	for name, check := range map[string]func(string) []string{"labels": labels, "coverage": coverage, "pending": pending, "hidden": hidden} {
		if got := check("../.."); len(got) > 0 {
			t.Errorf("%s on this repo: %v", name, got)
		}
	}
}

// Verifies: NFR-003 (AC-21 trace check)
func TestInetSockets(t *testing.T) {
	trace := `1233  execve("/tmp/x/bulwark-lab", ["bulwark-lab", "l01-notes"], 0x0 /* 9 vars */) = 0
1234  socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3
1238  socketpair(PF_INET, SOCK_STREAM, 0, [3, 4]) = -1
[pid  1235] connect(3, {sa_family=AF_UNIX, sun_path="/x"}, 110) = 0
1236  socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 5
[pid  1237] socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) = -1 EAFNOSUPPORT
`
	got := inetSockets(trace)
	if len(got) != 3 || !strings.Contains(got[0], "PF_INET") || !strings.Contains(got[1], "AF_INET,") || !strings.Contains(got[2], "AF_INET6") {
		t.Errorf("got %q", got)
	}
	if inetSockets("1 execve(\"/b/bulwark-lab\", [], 0) = 0\n1 socket(AF_UNIX, SOCK_STREAM, 0) = 3\n") != nil {
		t.Error("AF_UNIX flagged")
	}
	if inetSockets("1 socket(AF_UNIX, SOCK_STREAM, 0) = 3\n") == nil {
		t.Error("a trace without the lab execve must fail")
	}
}

// Verifies: FR-029 (spec 002 AC-34 hidden-character check)
func TestHiddenRunes(t *testing.T) {
	for in, want := range map[string]int{"plain\ttext\r\n": 0, "rlo\u202e": 1, "zwsp\u200b": 1, "tag\U000E0041": 1, "esc\x1b[": 1} {
		if got := hiddenRunes(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}
