// LAB ONLY: tests for the replay client against an in-memory fake server.
package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/lab/manifest"
	"go.yaml.in/yaml/v3"
)

// fake answers requests on a pipe and records what it received.
type fake struct {
	mu   sync.Mutex
	got  []map[string]any
	mute bool
}

func (f *fake) serve(in io.Reader, out io.Writer) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		var m map[string]any
		json.Unmarshal(sc.Bytes(), &m)
		f.mu.Lock()
		f.got = append(f.got, m)
		mute := f.mute
		f.mu.Unlock()
		id, ok := m["id"]
		if !ok || mute || m["method"] == "subscriptions/listen" {
			if m["method"] == "subscriptions/listen" {
				for i := 0; i < 100; i++ { // noise must not push out the awaited notification
					io.WriteString(out, `{"jsonrpc":"2.0","method":"notifications/progress"}`+"\n")
				}
				io.WriteString(out, `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`+"\n")
			}
			continue
		}
		result := map[string]any{}
		p, _ := m["params"].(map[string]any)
		switch m["method"] {
		case "tools/list":
			if p["cursor"] == nil {
				result["nextCursor"] = "page2"
			}
		case "tools/call":
			result["requestState"] = "opaque-state"
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
		out.Write(append(b, '\n'))
	}
}

func start(t *testing.T, rev string, f *fake) (*Client, *bytes.Buffer) {
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	go f.serve(sr, sw)
	t.Cleanup(func() { cw.Close(); sw.Close() })
	var tr bytes.Buffer
	c := New(cr, cw, rev, &syncBuf{b: &tr})
	c.Timeout = 2 * time.Second
	return c, &tr
}

type syncBuf struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func steps(t *testing.T, y string) []manifest.Step {
	var s []manifest.Step
	if err := yaml.Unmarshal([]byte(y), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

const script = `
- discover: {}
- list_tools: {}
- call: {name: read_file, arguments: {path: "{{lab_dir}}/private/secret.txt"}}
- call: {name: send_summary, arguments: {text: "{{canaries.plain}}"}, input_responses: {k: "{{canaries.secret}}"}, request_state_from_previous: true}
- subscribe: {tools_list_changed: true}
- wait_notification: {method: notifications/tools/list_changed}
- send_raw: {line: '{"not":"json-rpc"}'}
`

var vars = Vars{Canaries: map[string]string{"plain": "canary-plain-l01", "secret": "AKIAEXAMPLECANARYLAZ"}, LabDir: "/tmp/lab"}

// Verifies: FR-003 (AC-10, AC-12, AC-13, AC-14)
func TestRun2026(t *testing.T) {
	f := &fake{}
	c, tr := start(t, Rev2026, f)
	if err := c.Run(steps(t, script), vars); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	var methods []string
	for _, m := range f.got {
		methods = append(methods, str(m["method"]))
		if m["method"] == "initialize" {
			t.Error("sent initialize under 2026-07-28")
		}
		if _, isReq := m["id"]; isReq {
			meta, _ := m["params"].(map[string]any)["_meta"].(map[string]any)
			if meta["io.modelcontextprotocol/protocolVersion"] != Rev2026 || meta["io.modelcontextprotocol/clientCapabilities"] == nil {
				t.Errorf("%v: missing _meta: %v", m["method"], meta)
			}
		}
	}
	want := "server/discover tools/list tools/list tools/call tools/call subscriptions/listen "
	if got := strings.Join(methods, " "); got != want {
		t.Errorf("methods %q, want %q", got, want)
	}
	call := f.got[4]["params"].(map[string]any)
	if call["requestState"] != "opaque-state" || call["inputResponses"].(map[string]any)["k"] != "AKIAEXAMPLECANARYLAZ" {
		t.Errorf("retry params %v", call)
	}
	if f.got[3]["params"].(map[string]any)["arguments"].(map[string]any)["path"] != "/tmp/lab/private/secret.txt" {
		t.Error("lab_dir not substituted")
	}
	// AC-12: transcript has every line, numbered in order, both directions.
	lines := strings.Split(strings.TrimSpace(tr.String()), "\n")
	sends, recvs := 0, 0
	for i, l := range lines {
		var e struct {
			Seq       int
			Dir, Line string
		}
		json.Unmarshal([]byte(l), &e)
		if e.Seq != i+1 {
			t.Fatalf("transcript seq %d at line %d", e.Seq, i+1)
		}
		if e.Dir == "send" {
			sends++
		} else {
			recvs++
		}
	}
	if sends != 7 || recvs != 106 {
		t.Errorf("transcript: %d sent, %d received", sends, recvs)
	}
}

// Verifies: FR-003 (AC-11)
func TestRun2025Handshake(t *testing.T) {
	f := &fake{}
	c, _ := start(t, Rev2025, f)
	if err := c.Run(steps(t, "- discover: {}\n- list_tools: {}\n"), vars); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if str(f.got[0]["method"]) != "initialize" || str(f.got[1]["method"]) != "notifications/initialized" || str(f.got[2]["method"]) != "tools/list" {
		t.Errorf("order: %v %v %v", f.got[0]["method"], f.got[1]["method"], f.got[2]["method"])
	}
	if _, has := f.got[2]["params"].(map[string]any)["_meta"]; has {
		t.Error("2025-11-25 request carries 2026 _meta")
	}
}

// Verifies: FR-003 (AC-13)
func TestTimeout(t *testing.T) {
	c, _ := start(t, Rev2026, &fake{mute: true})
	c.Timeout = 30 * time.Millisecond
	if err := c.Run(steps(t, "- list_tools: {}\n"), vars); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func str(v any) string { s, _ := v.(string); return s }
