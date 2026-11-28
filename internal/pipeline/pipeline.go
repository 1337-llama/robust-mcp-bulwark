// Package pipeline runs every message through an ordered chain of
// interceptors (DESIGN.md §5.1). A panicking or failing interceptor blocks the
// message: the pipeline fails closed (spec 002 AC-26, NFR-005).
package pipeline

import (
	"context"
	"fmt"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

type Direction int

const (
	ClientToServer Direction = iota
	ServerToClient
)

type Verdict int

const (
	Forward Verdict = iota
	Modify
	Block
)

// Finding is one observation for the audit record (DESIGN.md §6.5).
type Finding struct {
	Analyzer string `json:"analyzer"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Location string `json:"location,omitempty"`
}

// Session is the per-connection state interceptors may read.
type Session struct {
	Mode     string // learn | warn | enforce
	Revision string
}

type Interceptor interface {
	Name() string
	Match(m *jsonrpc.Message, d Direction, s *Session) bool
	// Handle returns the verdict, the replacement message for Modify (or the
	// error response to send for Block, if any), findings, and control IDs.
	Handle(ctx context.Context, m *jsonrpc.Message, d Direction, s *Session) (Verdict, *jsonrpc.Message, []Finding, []string, error)
}

type Result struct {
	Verdict  Verdict
	Msg      *jsonrpc.Message // the message to forward, or the reply for a block
	Findings []Finding
	Controls []string
	Err      error // set when an interceptor failed; the message is blocked
}

type Chain []Interceptor

// Run passes m through every matching interceptor in order. Modify replaces
// the message for later interceptors; the first Block stops the chain.
func (c Chain) Run(ctx context.Context, m *jsonrpc.Message, d Direction, s *Session) (res Result) {
	res.Msg = m
	for _, ic := range c {
		if !ic.Match(res.Msg, d, s) {
			continue
		}
		v, out, f, controls, err := safeHandle(ctx, ic, res.Msg, d, s)
		res.Findings = append(res.Findings, f...)
		res.Controls = append(res.Controls, controls...)
		if err != nil {
			res.Verdict, res.Msg, res.Err = Block, nil, fmt.Errorf("%s: %w", ic.Name(), err)
			return res
		}
		switch v {
		case Modify:
			res.Verdict, res.Msg = Modify, out
		case Block:
			res.Verdict, res.Msg = Block, out
			return res
		}
	}
	return res
}

func safeHandle(ctx context.Context, ic Interceptor, m *jsonrpc.Message, d Direction, s *Session) (v Verdict, out *jsonrpc.Message, f []Finding, controls []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, out, err = Block, nil, fmt.Errorf("panic: %v", r)
		}
	}()
	return ic.Handle(ctx, m, d, s)
}
