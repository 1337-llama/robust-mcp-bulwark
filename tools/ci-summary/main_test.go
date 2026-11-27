package main

import (
	"bytes"
	"testing"
)

// Verifies: FR-005 (AC-20 results table)
func TestRender(t *testing.T) {
	var b bytes.Buffer
	render(&b, []cell{
		{Scenario: "L-02", Control: "pin:changed", Condition: "none", Revision: "2026-07-28", Status: "pass"},
		{Scenario: "L-01", Control: "analyzer:text.imperative/*", Condition: "enforce", Revision: "2026-07-28", Status: "pending"},
		{Scenario: "L-01", Control: "analyzer:text.imperative/*", Condition: "none", Revision: "2026-07-28", Status: "pass"},
		{Scenario: "L-01", Control: "analyzer:text.imperative/*", Condition: "warn", Revision: "2026-07-28", Status: "fail"},
	})
	want := "| Scenario | Control | Revision | Without Bulwark | warn | enforce |\n|---|---|---|---|---|---|\n" +
		"| L-01 | `analyzer:text.imperative/*` | 2026-07-28 | ✅ pass | ❌ fail | ⏳ pending |\n" +
		"| L-02 | `pin:changed` | 2026-07-28 | ✅ pass |  |  |\n"
	if b.String() != want {
		t.Errorf("got\n%s", b.String())
	}
}
