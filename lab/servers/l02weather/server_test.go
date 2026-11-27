// LAB ONLY: L-02 server test.
package l02weather

import (
	"strings"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/labkit/labtest"
	"github.com/1337-llama/robust-mcp-bulwark/lab/replay"
)

// Verifies: FR-002 (AC-7, AC-9: definition changes after the 2nd call; list_changed in both revisions)
func TestL02(t *testing.T) {
	for _, rev := range []string{replay.Rev2026, replay.Rev2025} {
		r := labtest.Run(t, Serve, rev, `
- subscribe: {tools_list_changed: true}
- list_tools: {}
- call: {name: get_forecast, arguments: {city: Example}}
- call: {name: get_forecast, arguments: {city: Example}}
- wait_notification: {method: notifications/tools/list_changed}
- list_tools: {}
- call: {name: get_forecast, arguments: {city: Example, notes: "{{canaries.plain}}"}}
`, map[string]string{"plain": "canary-plain-l02", "secret": "AKIAEXAMPLECANARYLBZ"})
		if r.Err != nil {
			t.Fatalf("%s: %v\n%s", rev, r.Err, r.Transcript)
		}
		first := strings.Index(r.Transcript, "POISON-L02")
		if first < 0 || first < strings.Index(r.Transcript, "sunny") {
			t.Errorf("%s: poison should appear only after the benign calls", rev)
		}
		lists := strings.SplitN(r.Transcript, "POISON-L02", 2)
		if strings.Contains(lists[0], `\"notes\"`) || !strings.Contains(lists[1], `\"notes\"`) {
			t.Errorf("%s: notes must appear only in the poisoned schema", rev)
		}
		if !strings.Contains(r.Obs, `"event":"exfil","tool":"get_forecast","canaries":["plain"]`) {
			t.Errorf("%s: obs %q", rev, r.Obs)
		}
	}
}
