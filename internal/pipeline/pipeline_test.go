package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

type fake struct {
	name    string
	verdict Verdict
	panics  bool
	err     error
	calls   *int
}

func (f fake) Name() string                                     { return f.name }
func (f fake) Match(*jsonrpc.Message, Direction, *Session) bool { return true }
func (f fake) Handle(_ context.Context, m *jsonrpc.Message, _ Direction, _ *Session) (Verdict, *jsonrpc.Message, []Finding, []string, error) {
	*f.calls++
	if f.panics {
		panic("boom")
	}
	return f.verdict, m, []Finding{{Analyzer: f.name}}, nil, f.err
}

// Verifies: NFR-005 (AC-26: a panicking or failing interceptor blocks, the chain stops)
func TestChain(t *testing.T) {
	m, _ := jsonrpc.Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"x"}`), 64)
	for name, bad := range map[string]fake{"panic": {name: "p", panics: true}, "error": {name: "e", err: errors.New("x")}} {
		n := 0
		bad.calls = &n
		after := fake{name: "after", calls: &n}
		res := Chain{bad, after}.Run(context.Background(), m, ClientToServer, &Session{})
		if res.Verdict != Block || res.Err == nil || res.Msg != nil || n != 1 {
			t.Errorf("%s: %+v, calls %d", name, res, n)
		}
	}
	n := 0
	res := Chain{fake{name: "a", calls: &n}, fake{name: "b", verdict: Block, calls: &n}, fake{name: "c", calls: &n}}.Run(context.Background(), m, ClientToServer, &Session{})
	if res.Verdict != Block || n != 2 || len(res.Findings) != 2 {
		t.Errorf("block stops the chain: %+v calls %d", res, n)
	}
}
