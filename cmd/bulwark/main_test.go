package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bulwark(t *testing.T, stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// Verifies: FR-020, FR-026, FR-027 (AC-1 wrap, AC-5 exit codes, AC-22 verify, AC-23 tail, AC-28, AC-30)
func TestCLI(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	t.Setenv("BULWARK_CONFIG", filepath.Join(state, "none.yaml"))
	if code, _, _ := bulwark(t, ""); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code, out, _ := bulwark(t, "", "version"); code != 0 || !strings.HasPrefix(out, "bulwark ") {
		t.Errorf("version: %d %q", code, out)
	}
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}` + "\n"
	code, out, errs := bulwark(t, req, "wrap", "--state-dir", state, "--", "sh", "-c", `read l; echo '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'; exit 4`)
	if code != 4 || !strings.Contains(out, `"result":{"tools":[]}`) || !strings.Contains(errs, "server id auto-") {
		t.Fatalf("wrap: code %d out %q err %q", code, out, errs)
	}
	if code, out, _ := bulwark(t, "", "audit", "verify", "--state-dir", state); code != 0 || !strings.Contains(out, "OK ") || !strings.Contains(out, "AR-6") {
		t.Errorf("verify: %d %q", code, out)
	}
	if code, out, _ := bulwark(t, "", "audit", "tail", "--state-dir", state, "--event", "start"); code != 0 || strings.Count(strings.TrimSpace(out), "\n") != 0 || !strings.Contains(out, "start") {
		t.Errorf("tail: %d %q", code, out)
	}
	files, _ := filepath.Glob(filepath.Join(state, "audit", "*", "*.jsonl"))
	b, _ := os.ReadFile(files[0])
	os.WriteFile(files[0], bytes.Replace(b, []byte(`"stop"`), []byte(`"stopX"`), 1), 0o600)
	if code, out, _ := bulwark(t, "", "audit", "verify", "--state-dir", state); code != 3 || !strings.Contains(out, "BROKEN") {
		t.Errorf("tampered verify: %d %q", code, out)
	}
	// AC-28 and AC-30: enforce refuses a bad config, and needs --server-id.
	os.WriteFile(filepath.Join(state, "bad.yaml"), []byte("version: 1\nnope: 1\n"), 0o600)
	if code, _, errs := bulwark(t, "", "wrap", "--mode", "enforce", "--server-id", "x", "--config", filepath.Join(state, "bad.yaml"), "--state-dir", state, "--", "true"); code != 1 || !strings.Contains(errs, "nope") {
		t.Errorf("bad config in enforce: %d %q", code, errs)
	}
	if code, _, errs := bulwark(t, "", "wrap", "--mode", "enforce", "--state-dir", state, "--", "true"); code != 1 || !strings.Contains(errs, "--server-id") {
		t.Errorf("enforce without id: %d %q", code, errs)
	}
}
