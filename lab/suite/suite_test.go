// LAB ONLY: the attack-suite runner (spec 001 AC-15, AC-16, AC-18, AC-19, AC-30).
// Every (scenario, run, condition, revision) cell is a subtest with a fresh
// temporary directory and a fresh lab-server process.
package suite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/manifest"
	"github.com/1337-llama/robust-mcp-bulwark/lab/replay"
)

var labBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bulwark-suite")
	if err != nil {
		panic(err)
	}
	labBin = os.Getenv("BULWARK_LAB_BIN") // prebuilt in CI, where the suite runs without a network
	if labBin == "" {
		labBin = filepath.Join(dir, "bulwark-lab")
		if out, err := exec.Command("go", "build", "-o", labBin, "../cmd/bulwark-lab").CombinedOutput(); err != nil {
			panic(string(out))
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Cell is one entry of results.json (DESIGN.md §6.8).
type Cell struct {
	Scenario  string `json:"scenario"`
	Control   string `json:"control"`
	Condition string `json:"condition"`
	Revision  string `json:"revision"`
	Status    string `json:"status"` // pass | fail | pending | timeout
	Detail    string `json:"detail,omitempty"`
}

// Verifies: FR-004, FR-005, NFR-003 (AC-30: never as root in CI)
func TestSuite(t *testing.T) {
	if os.Getenv("CI") == "true" && os.Geteuid() == 0 {
		t.Fatal("the suite must not run as root in CI (AC-30)")
	}
	allow, err := manifest.LoadAllowlist("../scenarios/allowlist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("../scenarios/L-*.yaml")
	if len(files) != 8 {
		t.Fatalf("want 8 manifests, found %d", len(files))
	}
	var cells []Cell
	for _, f := range files {
		m, err := manifest.Load(f, allow)
		if err != nil {
			t.Fatal(err)
		}
		for _, run := range m.Runs {
			for _, rev := range m.Revisions {
				for _, cond := range []string{"none", "warn", "enforce"} {
					c := Cell{Scenario: m.ID, Control: run.Control, Condition: cond, Revision: rev}
					t.Run(m.ID+"/"+run.Control+"/"+cond+"/"+rev, func(t *testing.T) {
						c.Status, c.Detail = runCell(t, m, run, cond, rev)
						if c.Status == "fail" || c.Status == "timeout" {
							t.Error(c.Detail)
						}
					})
					cells = append(cells, c)
				}
			}
		}
	}
	sort.Slice(cells, func(i, j int) bool {
		a, b := cells[i], cells[j]
		return a.Scenario+a.Control+a.Condition+a.Revision < b.Scenario+b.Control+b.Condition+b.Revision
	})
	out, _ := json.MarshalIndent(map[string]any{"header": map[string]string{"go": runtime.Version()}, "cells": cells}, "", "  ")
	if p := os.Getenv("BULWARK_RESULTS"); p != "" {
		if err := os.WriteFile(p, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func runCell(t *testing.T, m *manifest.Manifest, run manifest.Run, cond, rev string) (status, detail string) {
	if cond != "none" {
		if run.Pending != "" {
			return "pending", run.Pending // AC-16: reported, never failing
		}
		return "fail", "gateway conditions need the bulwark binary (spec 002 onward)"
	}
	transcript, obs, err := play(t, m, run, rev, nil)
	if err == replay.ErrTimeout || (err != nil && strings.Contains(err.Error(), "timeout")) {
		return "timeout", err.Error()
	}
	if err != nil {
		return "fail", err.Error()
	}
	if d := Check(run.Expect[cond], Observables(m.ID, transcript, obs), nil); d != "" {
		return "fail", d
	}
	return "pass", ""
}

// play runs one scenario script against a fresh lab server, optionally behind
// a wrapper command (for example bulwark wrap), and returns the transcript and
// the observation log.
func play(t *testing.T, m *manifest.Manifest, run manifest.Run, rev string, wrapper []string) (string, string, error) {
	dir := t.TempDir()
	for _, d := range []string{"private", "workspace"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "private", "secret.txt"), []byte(m.Canaries["plain"]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	canaries, _ := json.Marshal(m.Canaries)
	obsPath := filepath.Join(dir, "obs.jsonl")
	argv := append(append([]string{}, wrapper...), labBin, m.Server)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "BULWARK_LAB=1", "BULWARK_LAB_DIR="+dir, "BULWARK_LAB_OBS="+obsPath, "BULWARK_LAB_CANARIES="+string(canaries))
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var transcript bytes.Buffer
	c := replay.New(stdout, stdin, rev, &transcript)
	runErr := c.Run(m.Steps(run), replay.Vars{Canaries: m.Canaries, LabDir: dir})
	stdin.Close()
	<-c.Done()
	cmd.Wait()
	if runErr != nil {
		runErr = fmt.Errorf("%w\n%s", runErr, stderr.String())
	}
	obs, _ := os.ReadFile(obsPath)
	// The run directory differs per run; normalize it so runs can be compared.
	return strings.ReplaceAll(transcript.String(), dir, "{{lab_dir}}"), string(obs), runErr
}
