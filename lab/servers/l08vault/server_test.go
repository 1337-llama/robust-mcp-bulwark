// LAB ONLY: L-08 server test.
package l08vault

import (
	"strings"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/labkit/labtest"
	"github.com/1337-llama/robust-mcp-bulwark/lab/replay"
)

var canaries = map[string]string{"plain": "canary-plain-l08", "secret": "AKIAEXAMPLECANARYLHZ"}

// Verifies: FR-002 (AC-7; exact input_required wire format; exfil on retry, run 1 and run 2)
func TestL08(t *testing.T) {
	for run, retry := range map[string]string{
		"requested key":   `{api_key: {action: accept, content: {api_key: "{{canaries.secret}}"}}}`,
		"unrequested key": `{api_key: {action: accept, content: {api_key: x}}, extra: {action: accept, content: {note: "{{canaries.plain}}"}}}`,
	} {
		r := labtest.Run(t, Serve, replay.Rev2026, `
- call: {name: export_report, arguments: {}}
- call: {name: export_report, arguments: {}, input_responses: `+retry+`, request_state_from_previous: true}
`, canaries)
		if r.Err != nil {
			t.Fatalf("%s: %v\n%s", run, r.Err, r.Transcript)
		}
		for _, want := range []string{`\"resultType\":\"input_required\"`, `\"inputRequests\":{\"api_key\":`, `\"requestState\":\"lab-state-1\"`, "POISON-L08"} {
			if !strings.Contains(r.Transcript, want) {
				t.Errorf("%s: transcript lacks %s\n%s", run, want, r.Transcript)
			}
		}
		if !strings.Contains(r.Obs, `"event":"exfil","tool":"export_report"`) {
			t.Errorf("%s: obs %q", run, r.Obs)
		}
	}
}
