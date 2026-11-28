// Package mcprev assigns each message an MCP protocol revision (DESIGN.md
// §5.2; spec 002 AC-15 to AC-19) and detects revision-specific violations.
// Revisions: 2026-07-28 (per-request _meta, no initialize) and 2025-11-25.
package mcprev

import (
	"sync"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

const (
	Rev2026 = "2026-07-28"
	Rev2025 = "2025-11-25"
	Unknown = ""

	MetaVersion = "io.modelcontextprotocol/protocolVersion"
)

// Supported lists the revisions this gateway speaks (FR-036).
var Supported = []string{Rev2026, Rev2025}

func IsSupported(rev string) bool { return rev == Rev2026 || rev == Rev2025 }

// maxPending bounds the requests whose responses can still change the
// negotiation state; older entries are forgotten (an unanswered flood can't
// grow memory). The proxy's outstanding table (AC-14) bounds the rest.
const maxPending = 256

// Conn tracks one client connection's negotiation state. It is safe for
// concurrent use: Request runs on the client-to-server path, Response on the other.
type Conn struct {
	mu         sync.Mutex
	negotiated string            // version from a successful initialize result (legacy)
	modernOK   bool              // a modern request has succeeded
	pending    map[string]string // request id -> "initialize" | "modern" | "discover"
}

// Request assigns a revision to a client request or notification. Findings
// are "revision.unknown" or "revision.mixed".
func (c *Conn) Request(m *jsonrpc.Message) (rev string, findings []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	params := m.Root.Get("params")
	if v := params.Get("_meta").Get(MetaVersion); v != nil && v.Kind == jsonrpc.String {
		rev = v.Str
		if c.negotiated != "" {
			findings = append(findings, "revision.mixed")
		}
		c.track(m, "modern")
		if m.Method == "server/discover" {
			c.track(m, "discover")
		}
	} else if m.Method == "initialize" {
		if v := params.Get("protocolVersion"); v != nil && v.Kind == jsonrpc.String {
			rev = v.Str
		}
		if c.modernOK {
			findings = append(findings, "revision.mixed")
		}
		c.track(m, "initialize")
	} else if c.negotiated != "" {
		rev = c.negotiated
	}
	if !IsSupported(rev) {
		findings = append(findings, "revision.unknown")
	}
	return rev, findings
}

func (c *Conn) track(m *jsonrpc.Message, what string) {
	if m.Kind != jsonrpc.Request {
		return
	}
	if c.pending == nil {
		c.pending = map[string]string{}
	}
	if len(c.pending) >= maxPending { // evict a modern entry, never an in-flight initialize
		for k, v := range c.pending {
			if v != "initialize" {
				delete(c.pending, k)
				break
			}
		}
	}
	c.pending[string(jsonrpc.Serialize(m.ID))] = what
}

// Response updates the negotiation state from a server response to a client
// request. A failed server/discover probe followed by initialize is the
// 2026-07-28 stdio backward-compatibility pattern, so it never counts as modern.
func (c *Conn) Response(m *jsonrpc.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := string(jsonrpc.Serialize(m.ID))
	what, ok := c.pending[key]
	if !ok {
		return
	}
	delete(c.pending, key)
	result := m.Root.Get("result")
	if result == nil {
		return
	}
	switch what {
	case "initialize":
		if v := result.Get("protocolVersion"); v != nil && v.Kind == jsonrpc.String {
			c.negotiated = v.Str
		}
	case "modern", "discover":
		c.modernOK = true
	}
}

// ServerRequestViolation reports whether a server-to-client request is a
// protocol violation: under 2026-07-28 servers must not send requests on stdio (AC-18).
func ServerRequestViolation(rev string) bool { return rev == Rev2026 }

// mrtrMethods may return input_required under 2026-07-28 (AC-19).
var mrtrMethods = map[string]bool{"tools/call": true, "prompts/get": true, "resources/read": true}

// InputRequiredViolation reports whether a result for method carries
// resultType "input_required" where the 2026-07-28 revision does not allow it.
func InputRequiredViolation(rev, method string, result *jsonrpc.Value) bool {
	t := result.Get("resultType")
	return rev == Rev2026 && t != nil && t.Kind == jsonrpc.String && t.Str == "input_required" && !mrtrMethods[method]
}
