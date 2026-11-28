// Package proxy runs `bulwark wrap`: it starts the upstream server as a child
// process and passes every JSON-RPC line through the pipeline in both
// directions (DESIGN.md §5.1; spec 002 AC-1 to AC-14, AC-18, AC-19, AC-24,
// AC-26a). Only re-serialized, parsed messages are ever forwarded (AC-8).
package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/audit"
	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
	"github.com/1337-llama/robust-mcp-bulwark/internal/mcprev"
	"github.com/1337-llama/robust-mcp-bulwark/internal/pipeline"
)

// Auditor is the audit writer the proxy records to.
type Auditor interface {
	Write(audit.Record) error
	MAC([]byte) string
}

type Options struct {
	Mode           string // learn | warn | enforce
	ServerID       string
	MaxMessage     int
	MaxDepth       int
	MaxOutstanding int
	Chain          pipeline.Chain
	Conn           *mcprev.Conn
	Audit          Auditor
	GracePeriod    time.Duration // each shutdown wait (AC-4: 5 s)
}

type Proxy struct {
	o        Options
	cmd      *exec.Cmd
	sess     pipeline.Session
	sessMu   sync.Mutex
	toChild  *lockedWriter
	toClient *lockedWriter

	mu        sync.Mutex
	clientReq map[string]string // outstanding client requests: id -> method (AC-11)
	serverReq map[string]bool   // outstanding server requests, 2025-11-25 (AC-12)
	own       map[string]chan *jsonrpc.Message
	prefix    string
	counter   atomic.Uint64
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) line(b []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.w.Write(append(b, '\n'))
	return err
}

func key(id *jsonrpc.Value) string { return string(jsonrpc.Serialize(id)) }

// Run starts argv and proxies until the child exits. It returns the child's
// exit code; err is set only when Bulwark itself failed (exit 70, AC-5).
func Run(ctx context.Context, o Options, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if o.GracePeriod == 0 {
		o.GracePeriod = 5 * time.Second
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return 70, err
	}
	p := &Proxy{o: o, sess: pipeline.Session{Mode: o.Mode}, toClient: &lockedWriter{w: stdout},
		clientReq: map[string]string{}, serverReq: map[string]bool{}, own: map[string]chan *jsonrpc.Message{},
		prefix: "bulwark-" + hex.EncodeToString(b) + "-"}
	p.cmd = exec.Command(argv[0], argv[1:]...) // no shell; environment inherited unchanged (AC-1)
	p.cmd.Stderr = stderr                      // byte-for-byte (AC-3)
	ownGroup(p.cmd)
	childIn, err := p.cmd.StdinPipe()
	if err != nil {
		return 70, err
	}
	childOut, err := p.cmd.StdoutPipe()
	if err != nil {
		return 70, err
	}
	if err := p.cmd.Start(); err != nil {
		return 70, err
	}
	p.toChild = &lockedWriter{w: childIn}
	p.audit(audit.Record{Event: "start", Detail: map[string]any{"mode": o.Mode}})

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, termSignals...)
	defer signal.Stop(sigs)

	exited := make(chan error, 1)
	readDone := make(chan struct{})
	go func() { p.serverLoop(childOut); close(readDone) }()
	go func() { <-readDone; exited <- p.cmd.Wait() }()
	clientDone := make(chan struct{})
	go func() { p.clientLoop(stdin); childIn.Close(); close(clientDone) }()

	var waitErr error
	select {
	case waitErr = <-exited:
	case <-clientDone: // AC-4: stdin closed; give the child time, then escalate
		waitErr = p.shutdown(exited)
	case s := <-sigs: // AC-5a
		signalGroup(p.cmd, s)
		waitErr = p.shutdown(exited)
	case <-ctx.Done():
		signalGroup(p.cmd, sigTerm)
		waitErr = p.shutdown(exited)
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		code = ee.ExitCode()
		if code < 0 {
			code = 128 + 15
		}
	}
	p.audit(audit.Record{Event: "stop", Detail: map[string]any{"exit_code": code}})
	return code, nil
}

func (p *Proxy) shutdown(exited <-chan error) error {
	select {
	case err := <-exited:
		return err
	case <-time.After(p.o.GracePeriod):
	}
	signalGroup(p.cmd, sigTerm)
	select {
	case err := <-exited:
		return err
	case <-time.After(p.o.GracePeriod):
	}
	signalGroup(p.cmd, sigKill)
	return <-exited
}

// audit writes a record; in enforce mode a failure is reported so the caller
// blocks (AC-24). In learn/warn it only warns.
func (p *Proxy) audit(r audit.Record) bool {
	if p.o.Audit == nil {
		return true
	}
	r.ServerID = p.o.ServerID
	if err := p.o.Audit.Write(r); err != nil {
		fmt.Fprintln(os.Stderr, "bulwark: audit_error:", err)
		return p.o.Mode != "enforce"
	}
	return true
}

func (p *Proxy) revision() string {
	p.sessMu.Lock()
	defer p.sessMu.Unlock()
	return p.sess.Revision
}

func (p *Proxy) reply(w *lockedWriter, id *jsonrpc.Value, code int, msg string) {
	w.line(jsonrpc.ErrorResponse(id, code, msg, nil))
}

func (p *Proxy) record(event string, m *jsonrpc.Message, dir string, res *pipeline.Result, reason string) bool {
	r := audit.Record{Event: event, Direction: dir, Revision: p.revision(), Reason: reason}
	if m != nil {
		r.Method = m.Method
		if m.ID != nil {
			r.JSONRPCID = jsonrpc.Serialize(m.ID)
		}
		if args := m.Root.Get("params").Get("arguments"); args != nil && p.o.Audit != nil {
			b := jsonrpc.Serialize(args)
			r.ArgsMAC, r.ArgsBytes = p.o.Audit.MAC(b), len(b)
		}
	}
	if res != nil {
		r.Controls = res.Controls
		for _, f := range res.Findings {
			b, _ := jsonMarshal(f)
			r.Findings = append(r.Findings, b)
		}
		r.Decision = map[pipeline.Verdict]string{pipeline.Forward: "forward", pipeline.Modify: "modify", pipeline.Block: "block"}[res.Verdict]
	}
	return p.audit(r)
}

// clientLoop handles client -> server lines.
func (p *Proxy) clientLoop(r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := jsonrpc.ReadLine(br, p.o.MaxMessage)
		if err == jsonrpc.ErrTooLong { // AC-10: the id was not kept
			p.record("limit_exceeded", nil, "c2s", nil, "message size")
			p.reply(p.toClient, nil, jsonrpc.CodeLimit, "Message too large")
			continue
		}
		if err != nil {
			return
		}
		p.fromClient(line)
	}
}

func (p *Proxy) fromClient(line []byte) {
	m, err := jsonrpc.Parse(line, p.o.MaxDepth)
	if err != nil { // AC-7: route the error with the lenient scan only
		var je *jsonrpc.Error
		errors.As(err, &je)
		kind, id := jsonrpc.RouteScan(line)
		event := "protocol_violation"
		if je.Code == jsonrpc.CodeLimit {
			event = "limit_exceeded"
		}
		p.record(event, nil, "c2s", nil, je.Msg)
		switch kind {
		case jsonrpc.Notification:
		case jsonrpc.Response: // a reply to a 2025-11-25 server request
			if id != nil && p.takeServerReq(key(id)) {
				p.reply(p.toChild, id, jsonrpc.CodeInternal, "client protocol violation")
			}
		default:
			p.reply(p.toClient, id, je.Code, je.Msg)
		}
		return
	}
	if m.Kind == jsonrpc.Response {
		if !p.takeServerReq(key(m.ID)) { // AC-12: unknown id dropped
			p.record("protocol_violation", m, "c2s", nil, "response to no outstanding server request")
			return
		}
	}
	if m.Kind == jsonrpc.Request {
		p.mu.Lock()
		full := len(p.clientReq) >= p.o.MaxOutstanding
		if !full {
			p.clientReq[key(m.ID)] = m.Method
		}
		p.mu.Unlock()
		if full { // AC-14
			p.record("limit_exceeded", m, "c2s", nil, "outstanding requests")
			p.reply(p.toClient, m.ID, jsonrpc.CodeLimit, "Too many outstanding requests")
			return
		}
	}
	p.sessMu.Lock()
	res := p.o.Chain.Run(context.Background(), m, pipeline.ClientToServer, &p.sess)
	p.sessMu.Unlock()
	ok := p.record("call_decision", m, "c2s", &res, errString(res.Err))
	if res.Verdict == pipeline.Block || !ok {
		p.blockedFromClient(m, res.Msg, ok)
		return
	}
	p.toChild.line(jsonrpc.Serialize(res.Msg.Root))
}

// blockedFromClient tells the right party about a blocked client message (AC-26a).
func (p *Proxy) blockedFromClient(m *jsonrpc.Message, reply *jsonrpc.Message, audited bool) {
	switch m.Kind {
	case jsonrpc.Request:
		p.mu.Lock()
		delete(p.clientReq, key(m.ID))
		p.mu.Unlock()
		switch {
		case !audited && m.Method == "tools/call": // AC-24
			p.toClient.line(blockedToolResult(m.ID, "Blocked by MCP Bulwark (audit log unavailable)", p.revision() == mcprev.Rev2026))
		case reply != nil:
			p.toClient.line(jsonrpc.Serialize(reply.Root))
		default:
			p.reply(p.toClient, m.ID, jsonrpc.CodeInternal, "Blocked by MCP Bulwark")
		}
	case jsonrpc.Response: // the server's request gets an error instead
		p.reply(p.toChild, m.ID, jsonrpc.CodeInternal, "Blocked by MCP Bulwark")
	}
}

func (p *Proxy) takeServerReq(k string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	ok := p.serverReq[k]
	delete(p.serverReq, k)
	return ok
}

// serverLoop handles server -> client lines.
func (p *Proxy) serverLoop(r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := jsonrpc.ReadLine(br, p.o.MaxMessage)
		if err == jsonrpc.ErrTooLong {
			p.record("limit_exceeded", nil, "s2c", nil, "message size")
			continue
		}
		if err != nil {
			return
		}
		p.fromServer(line)
	}
}

func (p *Proxy) fromServer(line []byte) {
	m, err := jsonrpc.Parse(line, p.o.MaxDepth)
	if err != nil {
		kind, id := jsonrpc.RouteScan(line)
		p.record("protocol_violation", nil, "s2c", nil, err.Error())
		if kind == jsonrpc.Response && id != nil && p.takeClientReq(key(id)) {
			p.reply(p.toClient, id, jsonrpc.CodeInternal, "upstream protocol violation")
		}
		return
	}
	switch m.Kind {
	case jsonrpc.Response:
		k := key(m.ID)
		if m.ID.Kind == jsonrpc.String && len(m.ID.Str) > len(p.prefix) && m.ID.Str[:len(p.prefix)] == p.prefix {
			p.deliverOwn(k, m) // AC-13: never forwarded
			return
		}
		method, ok := p.clientMethod(k)
		if !ok { // AC-11
			p.record("protocol_violation", m, "s2c", nil, "response to no outstanding request")
			return
		}
		p.o.Conn.Response(m)
		if res := m.Root.Get("result"); res != nil && mcprev.InputRequiredViolation(p.revision(), method, res) { // AC-19
			p.record("protocol_violation", m, "s2c", nil, "input_required outside tools/call, prompts/get, resources/read")
			if p.o.Mode == "enforce" {
				p.takeClientReq(k)
				p.reply(p.toClient, m.ID, jsonrpc.CodeInternal, "upstream protocol violation")
				return
			}
		}
	case jsonrpc.Request:
		if mcprev.ServerRequestViolation(p.revision()) { // AC-18
			p.record("protocol_violation", m, "s2c", nil, "server request under 2026-07-28")
			if p.o.Mode == "enforce" {
				p.reply(p.toChild, m.ID, jsonrpc.CodeMethodNotFound, "Method not found")
				return
			}
		}
		p.mu.Lock()
		p.serverReq[key(m.ID)] = true
		p.mu.Unlock()
	}
	p.sessMu.Lock()
	res := p.o.Chain.Run(context.Background(), m, pipeline.ServerToClient, &p.sess)
	p.sessMu.Unlock()
	ok := p.record("call_decision", m, "s2c", &res, errString(res.Err))
	if m.Kind == jsonrpc.Response {
		p.takeClientReq(key(m.ID))
	}
	if res.Verdict == pipeline.Block || !ok {
		switch m.Kind {
		case jsonrpc.Response:
			p.reply(p.toClient, m.ID, jsonrpc.CodeInternal, "Blocked by MCP Bulwark")
		case jsonrpc.Request:
			p.takeServerReq(key(m.ID))
			p.reply(p.toChild, m.ID, jsonrpc.CodeInternal, "Blocked by MCP Bulwark")
		}
		return
	}
	p.toClient.line(jsonrpc.Serialize(res.Msg.Root))
}

func (p *Proxy) clientMethod(k string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m, ok := p.clientReq[k]
	return m, ok
}

func (p *Proxy) takeClientReq(k string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.clientReq[k]
	delete(p.clientReq, k)
	return ok
}

// Request sends a gateway-originated request to the server and waits for its
// response, which is never forwarded to the client (AC-13; used by spec 003).
func (p *Proxy) Request(ctx context.Context, method string, params *jsonrpc.Value) (*jsonrpc.Message, error) {
	id := &jsonrpc.Value{Kind: jsonrpc.String, Str: p.prefix + strconv.FormatUint(p.counter.Add(1), 10)}
	ch := make(chan *jsonrpc.Message, 1)
	p.mu.Lock()
	p.own[key(id)] = ch
	p.mu.Unlock()
	msg := &jsonrpc.Value{Kind: jsonrpc.Object, Members: []jsonrpc.Member{
		{Name: "jsonrpc", Value: &jsonrpc.Value{Kind: jsonrpc.String, Str: "2.0"}}, {Name: "id", Value: id},
		{Name: "method", Value: &jsonrpc.Value{Kind: jsonrpc.String, Str: method}}}}
	if params != nil {
		msg.Members = append(msg.Members, jsonrpc.Member{Name: "params", Value: params})
	}
	if err := p.toChild.line(jsonrpc.Serialize(msg)); err != nil {
		return nil, err
	}
	select {
	case m := <-ch:
		return m, nil
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.own, key(id))
		p.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (p *Proxy) deliverOwn(k string, m *jsonrpc.Message) {
	p.mu.Lock()
	ch := p.own[k]
	delete(p.own, k)
	p.mu.Unlock()
	if ch != nil {
		ch <- m
	}
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
