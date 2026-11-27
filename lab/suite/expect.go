// LAB ONLY: observables and expectation checks for the attack suite
// (spec 001 AC-15 to AC-17; DESIGN.md §1.4).
package suite

import (
	"bufio"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/1337-llama/robust-mcp-bulwark/lab/labkit"
)

// Observables computes poison_delivered, canary_exfiltrated, and
// forbidden_call_executed from a replay transcript and an observation log.
func Observables(scenario, transcript, obs string) map[string]bool {
	marker := "POISON-" + strings.ReplaceAll(scenario, "-", "")
	got := map[string]bool{"poison_delivered": false, "canary_exfiltrated": false, "forbidden_call_executed": false}
	sc := bufio.NewScanner(strings.NewReader(transcript))
	sc.Buffer(nil, 16<<20)
	for sc.Scan() {
		var e struct{ Dir, Line string }
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Dir == "recv" {
			var decoded any // undo JSON escapes, then Tag smuggling (L-06)
			if json.Unmarshal([]byte(e.Line), &decoded) == nil {
				b, _ := json.Marshal(decoded)
				if strings.Contains(labkit.DecodeTags(unescape(string(b))), marker) {
					got["poison_delivered"] = true
				}
			}
		}
	}
	for _, line := range strings.Split(obs, "\n") {
		var r struct{ Event string }
		if json.Unmarshal([]byte(line), &r) == nil {
			got["canary_exfiltrated"] = got["canary_exfiltrated"] || r.Event == "exfil"
			got["forbidden_call_executed"] = got["forbidden_call_executed"] || r.Event == "forbidden"
		}
	}
	return got
}

// unescape turns Go's JSON \u escapes of HTML characters back, so markers match.
func unescape(s string) string {
	return strings.NewReplacer(`<`, "<", `>`, ">", `&`, "&").Replace(s)
}

// Check compares observables (and, outside "none", the controls in the audit
// log) with a run's expectation for one condition. It returns "" on success.
func Check(expect map[string]any, got map[string]bool, audit []string) string {
	var diffs []string
	for k, want := range expect {
		if k == "controls_fired" {
			if d := matchControls(want.([]any), audit); d != "" {
				diffs = append(diffs, d)
			}
			continue
		}
		if got[k] != want.(bool) {
			diffs = append(diffs, fmt.Sprintf("%s = %v, want %v", k, got[k], want))
		}
	}
	sort.Strings(diffs)
	return strings.Join(diffs, "; ")
}

// matchControls requires the audit log's control IDs to equal the expected set;
// "analyzer:<name>/*" matches any rule of that analyzer (AC-17).
func matchControls(want []any, audit []string) string {
	seen := map[string]bool{}
	for _, a := range audit {
		seen[a] = true
	}
	matched := map[string]bool{}
	for _, w := range want {
		p := w.(string)
		hit := false
		for a := range seen {
			if a == p || (strings.HasSuffix(p, "/*") && strings.HasPrefix(a, strings.TrimSuffix(p, "*"))) {
				matched[a], hit = true, true
			}
		}
		if !hit {
			return "control " + p + " did not fire"
		}
	}
	var extra []string
	for a := range seen {
		if !matched[a] {
			extra = append(extra, a)
		}
	}
	if len(extra) > 0 {
		slices.Sort(extra)
		return "unexpected controls " + strings.Join(extra, ", ")
	}
	return ""
}

// AuditControls collects the "controls" of every record in a JSONL audit log.
func AuditControls(log string) []string {
	var out []string
	for _, line := range strings.Split(log, "\n") {
		var r struct{ Controls []string }
		if json.Unmarshal([]byte(line), &r) == nil {
			out = append(out, r.Controls...)
		}
	}
	return out
}
