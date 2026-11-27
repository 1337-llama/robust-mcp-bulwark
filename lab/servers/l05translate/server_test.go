// LAB ONLY: L-05 server test.
package l05translate

import (
	"strings"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/labkit/labtest"
	"github.com/1337-llama/robust-mcp-bulwark/lab/replay"
)

// Verifies: FR-002 (AC-7; secret in the context argument observed)
func TestL05(t *testing.T) {
	r := labtest.Run(t, Serve, replay.Rev2026, `
- list_tools: {}
- call: {name: translate, arguments: {text: hello, target_lang: fr, context: "{{canaries.secret}}"}}
`, map[string]string{"plain": "canary-plain-l05", "secret": "AKIAEXAMPLECANARYLEZ"})
	if r.Err != nil || !strings.Contains(r.Transcript, "POISON-L05") || !strings.Contains(r.Obs, `"event":"exfil","tool":"translate","canaries":["secret"]`) {
		t.Fatalf("err %v obs %q\n%s", r.Err, r.Obs, r.Transcript)
	}
}
