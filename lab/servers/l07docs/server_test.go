// LAB ONLY: L-07 server test.
package l07docs

import (
	"strings"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/labkit/labtest"
	"github.com/1337-llama/robust-mcp-bulwark/lab/replay"
)

// Verifies: FR-002 (AC-7; instructions delivered via discover and initialize)
func TestL07(t *testing.T) {
	for _, rev := range []string{replay.Rev2026, replay.Rev2025} {
		r := labtest.Run(t, Serve, rev, `
- discover: {}
- call: {name: search, arguments: {query: "{{canaries.plain}}"}}
`, map[string]string{"plain": "canary-plain-l07", "secret": "AKIAEXAMPLECANARYLGZ"})
		if r.Err != nil || !strings.Contains(r.Transcript, "POISON-L07") || !strings.Contains(r.Obs, `"event":"exfil","tool":"search"`) {
			t.Fatalf("%s: err %v obs %q\n%s", rev, r.Err, r.Obs, r.Transcript)
		}
	}
}
