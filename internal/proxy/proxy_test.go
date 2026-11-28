package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/audit"
	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
	"github.com/1337-llama/robust-mcp-bulwark/internal/mcprev"
	"github.com/1337-llama/robust-mcp-bulwark/internal/pipeline"
)

var fakeBin string

func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "fake")
	fakeBin = filepath.Join(dir, "fakeupstream")
	if out, err := exec.Command("go", "build", "-o", fakeBin, "./fakeupstream").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type run struct {
	in     *io.PipeWriter
	out    *bufio.Scanner
	stderr *bytes.Buffer
	done   chan int
}

func start(t *testing.T, fake, mode string) *run {
	t.Setenv("FAKE", fake)
	ir, iw := io.Pipe()
	or, ow := io.Pipe()
	r := &run{in: iw, out: bufio.NewScanner(or), stderr: &bytes.Buffer{}, done: make(chan int, 1)}
	conn := &mcprev.Conn{}
	o := Options{Mode: mode, ServerID: "t", MaxMessage: 1 << 16, MaxDepth: 64, MaxOutstanding: 2, Conn: conn,
		Chain: pipeline.Chain{pipeline.Revision{Conn: conn}}, GracePeriod: 200 * time.Millisecond}
	go func() {
		code, err := Run(context.Background(), o, []string{fakeBin}, ir, ow, r.stderr)
		if err != nil {
			t.Error(err)
		}
		ow.Close()
		r.done <- code
	}()
	return r
}

func (r *run) send(s string) { io.WriteString(r.in, s+"\n") }

func (r *run) recv(t *testing.T) *jsonrpc.Message {
	t.Helper()
	if !r.out.Scan() {
		t.Fatal("no output")
	}
	m, err := jsonrpc.Parse(r.out.Bytes(), 64)
	if err != nil {
		t.Fatalf("client got an invalid line %q: %v", r.out.Bytes(), err)
	}
	return m
}

const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

// Verifies: FR-020, FR-028 (AC-1, AC-2 transparency, AC-3 stderr, AC-8, AC-11 unknown ids, AC-4 exit)
func TestTransparentProxy(t *testing.T) {
	r := start(t, "stderr,unknownid", "warn")
	params := `{` + meta + `,"n":12345678901234567890123,"x":1.50e+10,"unknown":{"z":[true,null]}}`
	r.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":` + params + `}`)
	m := r.recv(t) // the unknown-id response (999) was dropped
	want, _ := jsonrpc.ParseValue([]byte(params), 64)
	if key(m.ID) != "1" || !reflect.DeepEqual(m.Root.Get("result").Get("echo"), want) {
		t.Fatalf("got %s", jsonrpc.Serialize(m.Root))
	}
	r.in.Close()
	if code := <-r.done; code != 0 {
		t.Errorf("exit code %d", code)
	}
	if !strings.Contains(r.stderr.String(), "fake-stderr \xff\x00 raw") {
		t.Errorf("stderr not passed through: %q", r.stderr.String())
	}
}

// Verifies: FR-028 (AC-7a, AC-7b, AC-10 client rejects; AC-14 outstanding limit)
func TestClientRejects(t *testing.T) {
	r := start(t, "mute", "warn")
	for in, want := range map[string]string{
		`not json`: `"id":null,"error":{"code":-32700`,
		`{"jsonrpc":"2.0","id":5,"id":6,"method":"x"}`:                                                             `"id":null,"error":{"code":-32600`,
		`{"jsonrpc":"2.0","id":7,"method":"x","params":{"s":"\ud800"}}`:                                            `"id":7,"error":{"code":-32600`,
		`{"jsonrpc":"2.0","id":8,"method":"x","params":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}`: `"id":8,"error":{"code":-32010`,
	} {
		r.send(in) // pipes are unbuffered: read each reply before the next send
		if got := string(jsonrpc.Serialize(r.recv(t).Root)); !strings.Contains(got, want) {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	for i := 1; i <= 3; i++ { // MaxOutstanding is 2; the server never answers
		r.send(`{"jsonrpc":"2.0","id":` + strconv.Itoa(10+i) + `,"method":"x","params":{` + meta + `}}`)
	}
	if got := string(jsonrpc.Serialize(r.recv(t).Root)); !strings.Contains(got, `"id":13,"error":{"code":-32010`) {
		t.Errorf("outstanding limit: %s", got)
	}
	r.in.Close()
	<-r.done
}

// Verifies: FR-028 (AC-7 server reject -> -32603 to the requester; AC-18 server request under 2026-07-28)
func TestServerRejects(t *testing.T) {
	r := start(t, "malformed", "enforce")
	r.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`)
	if got := string(jsonrpc.Serialize(r.recv(t).Root)); got != `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"upstream protocol violation"}}` {
		t.Errorf("got %s", got)
	}
	r.in.Close()
	<-r.done
}

// Verifies: FR-020 (AC-4 shutdown escalation, exit code passthrough, AC-5a no surviving grandchild)
func TestShutdown(t *testing.T) {
	r := start(t, "exit=3", "warn")
	r.send(`{"jsonrpc":"2.0","id":1,"method":"x","params":{` + meta + `}}`)
	r.recv(t)
	if code := <-r.done; code != 3 {
		t.Errorf("exit code %d, want 3", code)
	}

	r = start(t, "ignoreterm,grandchild", "warn")
	time.Sleep(100 * time.Millisecond)
	t0 := time.Now()
	r.in.Close()
	<-r.done
	if d := time.Since(t0); d > 2*time.Second {
		t.Errorf("shutdown took %v", d)
	}
	_, pid, _ := strings.Cut(r.stderr.String(), "grandchild=")
	n, _ := strconv.Atoi(strings.TrimSpace(pid))
	time.Sleep(100 * time.Millisecond)
	if n == 0 || alive(n) {
		t.Errorf("grandchild %d outlived the gateway", n)
	}
}

// Verifies: FR-031 (AC-13: gateway-originated ids, responses never forwarded)
func TestOwnRequests(t *testing.T) {
	var out bytes.Buffer
	p := &Proxy{o: Options{MaxDepth: 64, Conn: &mcprev.Conn{}}, toClient: &lockedWriter{w: &out}, toChild: &lockedWriter{w: io.Discard},
		clientReq: map[string]string{}, serverReq: map[string]bool{}, own: map[string]chan *jsonrpc.Message{}, prefix: "bulwark-abc-"}
	done := make(chan *jsonrpc.Message)
	go func() {
		m, _ := p.Request(context.Background(), "server/discover", nil)
		done <- m
	}()
	time.Sleep(20 * time.Millisecond)
	p.fromServer([]byte(`{"jsonrpc":"2.0","id":"bulwark-abc-1","result":{"ok":true}}`))
	if m := <-done; m == nil || m.Root.Get("result").Get("ok") == nil || out.Len() != 0 {
		t.Errorf("own response forwarded or lost: %q", out.String())
	}
}

// alive reports whether pid runs; a zombie (killed, not yet reaped by init in
// a container) counts as dead.
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true // no /proc (macOS): the signal check above is all we have
	}
	_, after, _ := strings.Cut(string(b), ") ")
	return !strings.HasPrefix(after, "Z")
}

type failingAudit struct{}

func (failingAudit) Write(audit.Record) error { return errors.New("disk full") }
func (failingAudit) MAC([]byte) string        { return "hmac-sha256:x" }

// Verifies: FR-026, NFR-005 (AC-24: audit failure blocks in enforce, warns in warn)
func TestAuditFailure(t *testing.T) {
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{` + meta + `,"name":"x","arguments":{}}}`
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + meta + `}}`
	for mode, want := range map[string][2]string{
		"enforce": {`"text":"Blocked by MCP Bulwark (audit log unavailable)"`, `"id":2,"error":{"code":-32603`},
		"warn":    {`"id":1,"result":{"echo"`, `"id":2,"result":{"echo"`},
	} {
		t.Setenv("FAKE", "")
		ir, iw := io.Pipe()
		or, ow := io.Pipe()
		out := bufio.NewScanner(or)
		conn := &mcprev.Conn{}
		o := Options{Mode: mode, ServerID: "t", MaxMessage: 1 << 16, MaxDepth: 64, MaxOutstanding: 8, Conn: conn,
			Chain: pipeline.Chain{pipeline.Revision{Conn: conn}}, Audit: failingAudit{}, GracePeriod: 200 * time.Millisecond}
		done := make(chan struct{})
		go func() { Run(context.Background(), o, []string{fakeBin}, ir, ow, io.Discard); ow.Close(); close(done) }()
		for i, in := range []string{call, list} {
			io.WriteString(iw, in+"\n")
			if !out.Scan() || !strings.Contains(out.Text(), want[i]) {
				t.Errorf("%s: got %q, want %s", mode, out.Text(), want[i])
			}
		}
		iw.Close()
		<-done
	}
}

// Verifies: FR-020 (AC-4: exit with the child's code as soon as it exits, even
// if a grandchild still holds stdout; the grandchild is cleaned up)
func TestChildExitWithGrandchild(t *testing.T) {
	ir, _ := io.Pipe() // the client never closes stdin
	conn := &mcprev.Conn{}
	o := Options{Mode: "warn", MaxMessage: 1 << 16, MaxDepth: 64, MaxOutstanding: 8, Conn: conn, Chain: pipeline.Chain{pipeline.Revision{Conn: conn}}}
	t0 := time.Now()
	code, err := Run(context.Background(), o, []string{"sh", "-c", "sleep 8 & exit 3"}, ir, io.Discard, io.Discard)
	if err != nil || code != 3 || time.Since(t0) > 3*time.Second {
		t.Fatalf("code %d err %v after %v", code, err, time.Since(t0))
	}
}

// A cancelled request frees its slot and its late response is dropped quietly.
func TestCancelled(t *testing.T) {
	r := start(t, "mute", "warn")
	for i := 1; i <= 2; i++ { // MaxOutstanding is 2
		r.send(`{"jsonrpc":"2.0","id":` + strconv.Itoa(i) + `,"method":"x","params":{` + meta + `}}`)
		r.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":` + strconv.Itoa(i) + `}}`)
	}
	r.send(`{"jsonrpc":"2.0","id":3,"method":"x","params":{` + meta + `}}`)
	r.send(`{"jsonrpc":"2.0","id":4,"method":"x","params":{` + meta + `}}`)
	r.send(`{"jsonrpc":"2.0","id":5,"method":"x","params":{` + meta + `}}`)
	if got := string(jsonrpc.Serialize(r.recv(t).Root)); !strings.Contains(got, `"id":5,"error":{"code":-32010`) {
		t.Errorf("cancelled requests still hold slots: %s", got)
	}
	r.in.Close()
	<-r.done
}
