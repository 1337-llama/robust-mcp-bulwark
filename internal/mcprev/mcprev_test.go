package mcprev

import (
	"slices"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

func msg(t *testing.T, s string) *jsonrpc.Message {
	m, err := jsonrpc.Parse([]byte(s), 64)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const (
	discov  = `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	initReq = `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`
	initOK  = `{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25"}}`
	plain   = `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`
)

// Verifies: FR-036 (AC-15, AC-16 unknown, AC-17 mixed and the discover-probe exception)
func TestAssign(t *testing.T) {
	var c Conn
	if rev, f := c.Request(msg(t, plain)); rev != Unknown || !slices.Contains(f, "revision.unknown") {
		t.Errorf("never negotiated: %q %v", rev, f)
	}
	// A failed discover probe, then initialize: the compatibility pattern, not mixed.
	c.Request(msg(t, discov))
	c.Response(msg(t, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}`))
	if _, f := c.Request(msg(t, initReq)); len(f) != 0 {
		t.Errorf("probe then initialize flagged: %v", f)
	}
	c.Response(msg(t, initOK))
	if rev, f := c.Request(msg(t, plain)); rev != Rev2025 || len(f) != 0 {
		t.Errorf("legacy-negotiated: %q %v", rev, f)
	}
	if rev, f := c.Request(msg(t, `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)); rev != Rev2026 || !slices.Contains(f, "revision.mixed") {
		t.Errorf("modern after legacy: %q %v", rev, f)
	}

	var d Conn // modern success, then initialize: mixed
	d.Request(msg(t, discov))
	d.Response(msg(t, `{"jsonrpc":"2.0","id":1,"result":{}}`))
	if _, f := d.Request(msg(t, initReq)); !slices.Contains(f, "revision.mixed") {
		t.Errorf("initialize after modern: %v", f)
	}
	if _, f := d.Request(msg(t, `{"jsonrpc":"2.0","id":9,"method":"x","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2024-11-05"}}}`)); !slices.Contains(f, "revision.unknown") {
		t.Errorf("unsupported revision: %v", f)
	}
}

// Verifies: FR-035, FR-036 (AC-18 server requests, AC-19 misplaced input_required)
func TestViolations(t *testing.T) {
	if !ServerRequestViolation(Rev2026) || ServerRequestViolation(Rev2025) {
		t.Error("server requests are violations only under 2026-07-28")
	}
	r := msg(t, `{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}`).Root.Get("result")
	if !InputRequiredViolation(Rev2026, "tools/list", r) || InputRequiredViolation(Rev2026, "tools/call", r) || InputRequiredViolation(Rev2025, "tools/list", r) {
		t.Error("input_required placement")
	}
}
