// LAB ONLY: tests for observables and control matching against fixture logs.
package suite

import "testing"

// Verifies: FR-004 (AC-17 control matching, with analyzer patterns)
func TestCheckControls(t *testing.T) {
	audit := AuditControls(`{"event":"call_decision","controls":["analyzer:text.imperative/hidden-instruction"]}
{"event":"tools_list","controls":[]}
not json
`)
	want := map[string]any{"poison_delivered": false, "controls_fired": []any{"analyzer:text.imperative/*"}}
	if d := Check(want, map[string]bool{"poison_delivered": false}, audit); d != "" {
		t.Errorf("pattern match failed: %s", d)
	}
	if d := Check(want, map[string]bool{"poison_delivered": false}, append(audit, "pin:changed")); d == "" {
		t.Error("extra control not reported")
	}
	if d := Check(want, map[string]bool{"poison_delivered": false}, nil); d == "" {
		t.Error("missing control not reported")
	}
	if d := Check(map[string]any{"canary_exfiltrated": true}, map[string]bool{"canary_exfiltrated": false}, nil); d == "" {
		t.Error("observable mismatch not reported")
	}
}

// Verifies: FR-004 (observables, including Tag-smuggled and JSON-escaped markers)
func TestObservables(t *testing.T) {
	tr := `{"seq":1,"dir":"send","line":"POISON-L01"}
{"seq":2,"dir":"recv","line":"{\"result\":{\"d\":\"\\u003cIMPORTANT\\u003e POISON-L01\"}}"}
`
	obs := `{"seq":1,"event":"exfil"}`
	got := Observables("L-01", tr, obs)
	if !got["poison_delivered"] || !got["canary_exfiltrated"] || got["forbidden_call_executed"] {
		t.Errorf("got %v", got)
	}
	if Observables("L-01", `{"seq":1,"dir":"send","line":"POISON-L01"}`, "")["poison_delivered"] {
		t.Error("sent text counted as delivered")
	}
}
