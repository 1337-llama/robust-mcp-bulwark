// LAB ONLY: spec 002 AC-6 (the M1 exit): bulwark wrap --mode learn changes
// nothing a client or server can observe.
package suite

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/manifest"
)

// received returns the parsed messages the replay client received, in order.
func received(transcript string) []any {
	var out []any
	for _, line := range strings.Split(strings.TrimSpace(transcript), "\n") {
		var e struct{ Dir, Line string }
		var msg any
		if json.Unmarshal([]byte(line), &e) == nil && e.Dir == "recv" && json.Unmarshal([]byte(e.Line), &msg) == nil {
			out = append(out, msg)
		}
	}
	return out
}

// Verifies: FR-020, FR-028 (spec 002 AC-6 transparency for every scenario and revision)
func TestTransparency(t *testing.T) {
	bin := os.Getenv("BULWARK_BIN")
	if bin == "" {
		bin = filepath.Join(t.TempDir(), "bulwark")
		if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/bulwark").CombinedOutput(); err != nil {
			t.Fatal(string(out))
		}
	}
	allow, _ := manifest.LoadAllowlist("../scenarios/allowlist.yaml")
	files, _ := filepath.Glob("../scenarios/L-*.yaml")
	for _, f := range files {
		m, err := manifest.Load(f, allow)
		if err != nil {
			t.Fatal(err)
		}
		for _, rev := range m.Revisions {
			t.Run(m.ID+"/"+rev, func(t *testing.T) {
				state := t.TempDir()
				wrapper := []string{bin, "wrap", "--mode", "learn", "--server-id", strings.ToLower(m.ID), "--state-dir", state, "--config", filepath.Join(state, "none.yaml"), "--"}
				tr0, obs0, err0 := play(t, m, m.Runs[0], rev, nil)
				tr1, obs1, err1 := play(t, m, m.Runs[0], rev, wrapper)
				if err0 != nil || err1 != nil {
					t.Fatalf("direct: %v\nwrapped: %v", err0, err1)
				}
				if obs0 != obs1 {
					t.Errorf("observation logs differ:\n%s\n---\n%s", obs0, obs1)
				}
				if a, b := received(tr0), received(tr1); !reflect.DeepEqual(a, b) {
					t.Errorf("received messages differ (%d vs %d)", len(a), len(b))
				}
			})
		}
	}
}
