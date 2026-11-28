package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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
	// A broken config whose mode can't be read fails closed when --mode is not given.
	os.WriteFile(filepath.Join(state, "bad2.yaml"), []byte("version: 1\nservers: {web: {mode: enforce}}\ntypo: 1\n"), 0o600)
	if code, _, _ := bulwark(t, "", "wrap", "--server-id", "web", "--config", filepath.Join(state, "bad2.yaml"), "--state-dir", state, "--", "true"); code != 1 {
		t.Errorf("broken config without --mode must not run: %d", code)
	}
	if code, _, _ := bulwark(t, "", "wrap", "--server-id", "../x", "--state-dir", state, "--", "true"); code != 1 {
		t.Errorf("path-like server id accepted: %d", code)
	}
}

// Verifies: FR-020 (AC-5a: SIGTERM is forwarded, a stop record is written, no grandchild survives)
func TestSignal(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bulwark")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	state := filepath.Join(dir, "state")
	cmd := exec.Command(bin, "wrap", "--server-id", "sig", "--state-dir", state, "--config", filepath.Join(dir, "none.yaml"), "--",
		"sh", "-c", "sleep 60 & echo $! >&2; wait")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, _ := cmd.StdinPipe() // kept open: only the signal ends the run
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatal("gateway did not exit after SIGTERM")
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(strings.Split(stderr.String(), "\n")[0]))
	if pid == 0 || syscall.Kill(pid, 0) == nil && !zombie(pid) {
		t.Errorf("grandchild %d survived (stderr %q)", pid, stderr.String())
	}
	files, _ := filepath.Glob(filepath.Join(state, "audit", "sig", "*.jsonl"))
	if b, _ := os.ReadFile(files[0]); !bytes.Contains(b, []byte(`"event":"stop"`)) {
		t.Error("no stop record")
	}
}

func zombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	_, after, _ := strings.Cut(string(b), ") ")
	return err == nil && strings.HasPrefix(after, "Z")
}
