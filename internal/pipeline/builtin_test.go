package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
	"github.com/1337-llama/robust-mcp-bulwark/internal/mcprev"
)

func parse(t *testing.T, s string) *jsonrpc.Message {
	m, err := jsonrpc.Parse([]byte(s), 64)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Verifies: FR-036 (AC-15, AC-16: -32022 in enforce, finding in warn)
func TestRevisionInterceptor(t *testing.T) {
	req := `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`
	for mode, want := range map[string]Verdict{"enforce": Block, "warn": Forward} {
		s := &Session{Mode: mode}
		res := Chain{Revision{Conn: &mcprev.Conn{}}}.Run(context.Background(), parse(t, req), ClientToServer, s)
		if res.Verdict != want || len(res.Findings) != 1 || res.Findings[0].Rule != "revision.unknown" {
			t.Errorf("%s: %+v", mode, res)
		}
		if mode == "enforce" && res.Msg.Root.Get("error").Get("code").Num != "-32022" {
			t.Errorf("reply %s", jsonrpc.Serialize(res.Msg.Root))
		}
	}
}

// Verifies: NFR-013 (AC-33: excess dropped, one aggregated record, list_changed processed and coalesced)
func TestRateLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	stale := 0
	r := &RateLimit{PerSecond: 2, Now: func() time.Time { return now }, OnListChanged: func() { stale++ }}
	note := parse(t, `{"jsonrpc":"2.0","method":"notifications/progress"}`)
	lc := parse(t, `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)
	var fwd int
	for i := 0; i < 5; i++ {
		if res := (Chain{r}).Run(context.Background(), note, ServerToClient, &Session{}); res.Verdict == Forward {
			fwd++
		}
	}
	a := Chain{r}.Run(context.Background(), lc, ServerToClient, &Session{})
	b := Chain{r}.Run(context.Background(), lc, ServerToClient, &Session{})
	if fwd != 2 || a.Verdict != Forward || b.Verdict != Block || stale != 2 {
		t.Fatalf("fwd %d, list_changed %v %v, stale %d", fwd, a.Verdict, b.Verdict, stale)
	}
	now = now.Add(time.Second)
	res := Chain{r}.Run(context.Background(), note, ServerToClient, &Session{})
	if res.Verdict != Forward || len(res.Findings) != 1 || res.Findings[0].Location != "3 notifications dropped" {
		t.Errorf("aggregated record: %+v", res)
	}
}
