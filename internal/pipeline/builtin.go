package pipeline

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
	"github.com/1337-llama/robust-mcp-bulwark/internal/mcprev"
)

// Revision assigns each client message a revision (AC-15) and, in enforce
// mode, answers requests with an unknown or unsupported revision with -32022
// (AC-16). Findings: revision.unknown, revision.mixed (AC-17).
type Revision struct{ Conn *mcprev.Conn }

func (Revision) Name() string { return "revision" }

func (Revision) Match(m *jsonrpc.Message, d Direction, _ *Session) bool {
	return d == ClientToServer && m.Kind != jsonrpc.Response
}

func (r Revision) Handle(_ context.Context, m *jsonrpc.Message, _ Direction, s *Session) (Verdict, *jsonrpc.Message, []Finding, []string, error) {
	rev, names := r.Conn.Request(m)
	s.Revision = rev
	var findings []Finding
	unknown := false
	for _, n := range names {
		findings = append(findings, Finding{Analyzer: "revision", Rule: n, Severity: "medium"})
		unknown = unknown || n == "revision.unknown"
	}
	if unknown && s.Mode == "enforce" && m.Kind == jsonrpc.Request {
		reply, err := jsonrpc.Parse(jsonrpc.UnsupportedVersion(m.ID, mcprev.Supported), 8)
		return Block, reply, findings, nil, err
	}
	return Forward, m, findings, nil, nil
}

// RateLimit drops server notifications above PerSecond (AC-33), reporting one
// aggregated rate_limited finding per window. tools/list_changed is never
// dropped unprocessed: OnListChanged always runs, and repeats are forwarded
// coalesced to at most one per second.
type RateLimit struct {
	PerSecond     int
	Now           func() time.Time
	OnListChanged func()

	mu          sync.Mutex
	window      time.Time
	count       int
	dropped     int
	lastListFwd time.Time
}

func (*RateLimit) Name() string { return "ratelimit" }

func (*RateLimit) Match(m *jsonrpc.Message, d Direction, _ *Session) bool {
	return d == ServerToClient && m.Kind == jsonrpc.Notification
}

func (r *RateLimit) Handle(_ context.Context, m *jsonrpc.Message, _ Direction, _ *Session) (Verdict, *jsonrpc.Message, []Finding, []string, error) {
	if m.Method == "notifications/tools/list_changed" && r.OnListChanged != nil {
		r.OnListChanged() // outside the lock, so a re-entrant callback can't deadlock
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.Now()
	var findings []Finding
	if now.Sub(r.window) >= time.Second {
		findings = r.flushLocked()
		r.window, r.count = now, 0
	}
	if m.Method == "notifications/tools/list_changed" {
		if now.Sub(r.lastListFwd) < time.Second {
			return Block, nil, findings, nil, nil // coalesced, already processed
		}
		r.lastListFwd = now
		return Forward, m, findings, nil, nil
	}
	r.count++
	if r.count > r.PerSecond {
		r.dropped++
		return Block, nil, findings, nil, nil
	}
	return Forward, m, findings, nil, nil
}

// Flush returns the pending aggregated finding, if any (call on shutdown).
func (r *RateLimit) Flush() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked()
}

func (r *RateLimit) flushLocked() []Finding {
	if r.dropped == 0 {
		return nil
	}
	f := []Finding{{Analyzer: "limits", Rule: "rate_limited", Severity: "low", Location: strconv.Itoa(r.dropped) + " notifications dropped"}}
	r.dropped = 0
	return f
}
