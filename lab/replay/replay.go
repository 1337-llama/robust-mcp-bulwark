// LAB ONLY: the scripted "hijacked agent". It speaks raw JSON-RPC over a lab
// server's stdio, exactly as a script says, and records every line (spec 001
// AC-10 to AC-14; MCP 2026-07-28 schema, with 2025-11-25 compatibility).
package replay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/lab/manifest"
)

const (
	Rev2026 = "2026-07-28"
	Rev2025 = "2025-11-25"
)

// ErrTimeout means a step waited longer than the step timeout (AC-13).
var ErrTimeout = errors.New("replay: timeout")

type Client struct {
	rev     string
	w       io.Writer
	Timeout time.Duration

	mu      sync.Mutex
	nextID  int
	seq     int
	waiting map[int]chan json.RawMessage
	seen    map[string]int // notifications received, by method
	used    map[string]int // notifications consumed by wait_notification
	noteSig chan struct{}
	readErr error
	trans   io.Writer
	done    chan struct{}
	last    map[string]any // result of the previous call (for requestState echo)
}

// New starts reading r. transcript receives one JSON line per message (AC-12).
func New(r io.Reader, w io.Writer, rev string, transcript io.Writer) *Client {
	c := &Client{rev: rev, w: w, Timeout: 5 * time.Second, waiting: map[int]chan json.RawMessage{},
		seen: map[string]int{}, used: map[string]int{}, noteSig: make(chan struct{}, 1), trans: transcript, done: make(chan struct{})}
	go c.read(r)
	return c
}

func (c *Client) record(dir, line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	b, _ := json.Marshal(struct {
		Seq  int    `json:"seq"`
		Dir  string `json:"dir"`
		Line string `json:"line"`
	}{c.seq, dir, line})
	c.trans.Write(append(b, '\n'))
}

func (c *Client) read(r io.Reader) {
	defer close(c.done)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		c.record("recv", line)
		var m struct {
			ID     *int   `json:"id"`
			Method string `json:"method"`
		}
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		switch {
		case m.Method != "" && m.ID == nil:
			c.mu.Lock()
			c.seen[m.Method]++ // counted, not buffered, so a flood can't push out the one we wait for
			c.mu.Unlock()
			select {
			case c.noteSig <- struct{}{}:
			default:
			}
		case m.Method != "" && m.ID != nil:
			// Server-initiated request: not supported by the replay client.
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": *m.ID, "error": map[string]any{"code": -32601, "message": "Method not found"}})
			c.SendRaw(string(b))
		case m.Method == "" && m.ID != nil:
			c.mu.Lock()
			ch := c.waiting[*m.ID]
			delete(c.waiting, *m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- json.RawMessage(line)
			}
		}
	}
	if err := sc.Err(); err != nil {
		c.record("error", err.Error())
		c.mu.Lock()
		c.readErr = err
		c.mu.Unlock()
	}
}

// Done is closed when the server's stdout reaches EOF.
func (c *Client) Done() <-chan struct{} { return c.done }

// SendRaw writes one line verbatim (AC-14). The send_raw script step applies
// template substitution ({{canaries.*}}, {{lab_dir}}) to the line first.
func (c *Client) SendRaw(line string) error {
	c.record("send", line)
	_, err := io.WriteString(c.w, line+"\n")
	return err
}

func (c *Client) send(msg map[string]any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.SendRaw(string(b))
}

// meta is the per-request _meta of 2026-07-28 (AC-10).
func (c *Client) meta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    Rev2026,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
}

// start sends a request and returns the channel its response arrives on.
func (c *Client) start(method string, params map[string]any) (int, chan json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}
	if c.rev == Rev2026 {
		params["_meta"] = c.meta()
	}
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan json.RawMessage, 1)
	c.waiting[id] = ch
	c.mu.Unlock()
	return id, ch, c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

// Request sends a request and waits for the response with the same id (AC-13).
func (c *Client) Request(method string, params map[string]any) (json.RawMessage, error) {
	_, ch, err := c.start(method, params)
	if err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.readErr != nil {
			return nil, fmt.Errorf("replay: reading server output: %w", c.readErr)
		}
		return nil, errors.New("replay: server closed stdout")
	case <-time.After(c.Timeout):
		return nil, ErrTimeout
	}
}

// Init performs the 2025-11-25 handshake (AC-11); it is a no-op for 2026-07-28.
func (c *Client) Init() error {
	if c.rev != Rev2025 {
		return nil
	}
	if _, err := c.Request("initialize", map[string]any{
		"protocolVersion": Rev2025,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "bulwark-replay", "version": "0"},
	}); err != nil {
		return err
	}
	return c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

// Vars substitutes {{canaries.<name>}} and {{lab_dir}} in every string.
type Vars struct {
	Canaries map[string]string
	LabDir   string
}

func (v Vars) apply(x any) any {
	switch t := x.(type) {
	case string:
		t = strings.ReplaceAll(t, "{{lab_dir}}", v.LabDir)
		for k, val := range v.Canaries {
			t = strings.ReplaceAll(t, "{{canaries."+k+"}}", val)
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = v.apply(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = v.apply(e)
		}
		return out
	}
	return x
}

// Run executes a script. It stops at the first error; ErrTimeout means the
// cell's result is "timeout" (AC-13).
func (c *Client) Run(steps []manifest.Step, v Vars) error {
	if err := c.Init(); err != nil {
		return err
	}
	for i, s := range steps {
		if err := c.step(s, v); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
	}
	return nil
}

func (c *Client) step(s manifest.Step, v Vars) error {
	switch {
	case s.Discover != nil:
		if c.rev == Rev2026 {
			_, err := c.Request("server/discover", nil)
			return err
		}
	case s.ListTools != nil:
		cursor := ""
		for page := 0; page < 100; page++ {
			params := map[string]any{}
			if cursor != "" {
				params["cursor"] = cursor
			}
			resp, err := c.Request("tools/list", params)
			if err != nil {
				return err
			}
			var r struct {
				Result struct{ NextCursor string } `json:"result"`
			}
			json.Unmarshal(resp, &r)
			if cursor = r.Result.NextCursor; cursor == "" {
				return nil
			}
		}
		return errors.New("tools/list: more than 100 pages")
	case s.Call != nil:
		params := map[string]any{"name": s.Call.Name, "arguments": v.apply(map[string]any(s.Call.Arguments))}
		if s.Call.InputResponses != nil {
			params["inputResponses"] = v.apply(map[string]any(s.Call.InputResponses))
		}
		if s.Call.RequestStateFromPrevious {
			if st, ok := c.last["requestState"].(string); ok {
				params["requestState"] = st
			}
		}
		resp, err := c.Request("tools/call", params)
		if err != nil {
			return err
		}
		var r struct {
			Result map[string]any `json:"result"`
		}
		json.Unmarshal(resp, &r)
		c.last = r.Result
	case s.Subscribe != nil:
		if c.rev == Rev2026 { // a long-lived stream: its response only ends it
			_, _, err := c.start("subscriptions/listen", map[string]any{
				"notifications": map[string]any{"toolsListChanged": (*s.Subscribe)["tools_list_changed"]},
			})
			return err
		}
	case s.WaitNotification != nil:
		method := s.WaitNotification.Method
		deadline := time.After(c.Timeout)
		for {
			c.mu.Lock()
			ok := c.seen[method] > c.used[method]
			if ok {
				c.used[method]++
			}
			c.mu.Unlock()
			if ok {
				return nil
			}
			select {
			case <-c.noteSig:
			case <-deadline:
				return ErrTimeout
			}
		}
	case s.SendRaw != nil:
		return c.SendRaw(v.apply(s.SendRaw.Line).(string))
	}
	return nil
}
