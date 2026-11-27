// Package jsonrpc reads, strictly parses, classifies, and re-serializes
// JSON-RPC 2.0 lines (spec 002 AC-2, AC-7 to AC-10; DESIGN.md §5.1).
// Forwarded messages are always the re-serialized form of what was parsed.
package jsonrpc

import (
	"bufio"
	"bytes"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/go-json-experiment/json/jsontext"
)

type Kind int

const (
	Invalid Kind = iota
	Request
	Response
	Notification
)

type ValueKind int

const (
	Object ValueKind = iota
	Array
	String
	Number
	Bool
	Null
)

// Value is an ordered JSON tree; numbers keep their exact literal.
type Value struct {
	Kind    ValueKind
	Members []Member
	Elems   []*Value
	Str     string
	Num     string
	Bool    bool
}

type Member struct {
	Name  string
	Value *Value
}

// Get returns the member named name, or nil.
func (v *Value) Get(name string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	for _, m := range v.Members {
		if m.Name == name {
			return m.Value
		}
	}
	return nil
}

type Message struct {
	Kind   Kind
	ID     *Value
	Method string
	Root   *Value
}

// Error carries the JSON-RPC error code a rejected line gets (AC-7a, AC-7b, AC-10).
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%d: %s", e.Code, e.Msg) }

const (
	CodeParse   = -32700
	CodeInvalid = -32600
	CodeLimit   = -32010
)

// ErrTooLong is returned by ReadLine for a line over the cap; the rest of the
// line has been discarded, so the next call reads the next line (AC-10).
var ErrTooLong = &Error{CodeLimit, "message exceeds the size limit"}

// ReadLine returns the next line without its newline, never buffering more
// than max+1 bytes of it.
func ReadLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > max+1 { // +1 for the newline
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			if err != nil && err != io.EOF {
				return nil, err
			}
			return nil, ErrTooLong
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && (err != io.EOF || len(line) == 0) {
			return nil, err
		}
		return bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r")), nil
	}
}

// Parse strictly parses one JSON-RPC 2.0 message. Syntax errors give
// CodeParse; valid JSON that is rejected (duplicate names, invalid UTF-8, lone
// surrogates, too deep, not a single JSON-RPC 2.0 object) gives CodeInvalid.
func Parse(line []byte, maxDepth int) (*Message, error) {
	if !stdjson.Valid(line) { // the lenient parser accepts what strict JSON-RPC rejects below
		return nil, &Error{CodeParse, "parse error"}
	}
	d := jsontext.NewDecoder(bytes.NewReader(line))
	root, err := parseValue(d, 0, maxDepth)
	if err == nil {
		if _, err = d.ReadToken(); err == io.EOF {
			err = nil
		} else if err == nil {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		return nil, &Error{CodeInvalid, "invalid request: " + err.Error()}
	}
	m, err := classify(root)
	if err != nil {
		return nil, &Error{CodeInvalid, "invalid request: " + err.Error()}
	}
	return m, nil
}

func parseValue(d *jsontext.Decoder, depth, maxDepth int) (*Value, error) {
	t, err := d.ReadToken()
	if err != nil {
		return nil, err
	}
	switch t.Kind() {
	case '{', '[':
		if depth+1 > maxDepth {
			return nil, fmt.Errorf("nesting deeper than %d", maxDepth)
		}
		v := &Value{Kind: Object}
		if t.Kind() == '[' {
			v.Kind = Array
		}
		for d.PeekKind() != '}' && d.PeekKind() != ']' {
			if v.Kind == Object {
				tok, err := d.ReadToken()
				if err != nil {
					return nil, err
				}
				name := tok.String() // a token is valid only until the next decoder call
				e, err := parseValue(d, depth+1, maxDepth)
				if err != nil {
					return nil, err
				}
				v.Members = append(v.Members, Member{name, e})
			} else {
				e, err := parseValue(d, depth+1, maxDepth)
				if err != nil {
					return nil, err
				}
				v.Elems = append(v.Elems, e)
			}
		}
		if _, err := d.ReadToken(); err != nil {
			return nil, err
		}
		return v, nil
	case '"':
		return &Value{Kind: String, Str: t.String()}, nil
	case '0':
		return &Value{Kind: Number, Num: t.String()}, nil
	case 't', 'f':
		return &Value{Kind: Bool, Bool: t.Bool()}, nil
	case 'n':
		return &Value{Kind: Null}, nil
	}
	return nil, fmt.Errorf("unexpected token %v", t.Kind())
}

func classify(root *Value) (*Message, error) {
	if root.Kind != Object {
		return nil, errors.New("not a single JSON-RPC object (batches are not supported)")
	}
	if v := root.Get("jsonrpc"); v == nil || v.Kind != String || v.Str != "2.0" {
		return nil, errors.New(`"jsonrpc" must be "2.0"`)
	}
	m := &Message{Root: root, ID: root.Get("id")}
	if m.ID != nil && m.ID.Kind != String && m.ID.Kind != Number && m.ID.Kind != Null {
		return nil, errors.New("id must be a string or a number")
	}
	method := root.Get("method")
	switch {
	case method != nil:
		if method.Kind != String {
			return nil, errors.New("method must be a string")
		}
		m.Method = method.Str
		m.Kind = Notification
		if m.ID != nil {
			m.Kind = Request
		}
	case root.Get("result") != nil || root.Get("error") != nil:
		if (root.Get("result") != nil) == (root.Get("error") != nil) || m.ID == nil {
			return nil, errors.New("a response needs an id and exactly one of result and error")
		}
		m.Kind = Response
	default:
		return nil, errors.New("neither a request, a notification, nor a response")
	}
	return m, nil
}

// Serialize writes v compactly, keeping member order and number literals.
func Serialize(v *Value) []byte {
	var b bytes.Buffer
	write(&b, v)
	return b.Bytes()
}

func write(b *bytes.Buffer, v *Value) {
	switch v.Kind {
	case Object:
		b.WriteByte('{')
		for i, m := range v.Members {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, m.Name)
			b.WriteByte(':')
			write(b, m.Value)
		}
		b.WriteByte('}')
	case Array:
		b.WriteByte('[')
		for i, e := range v.Elems {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, e)
		}
		b.WriteByte(']')
	case String:
		writeString(b, v.Str)
	case Number:
		b.WriteString(v.Num)
	case Bool:
		b.WriteString(strconv.FormatBool(v.Bool))
	case Null:
		b.WriteString("null")
	}
}

func writeString(b *bytes.Buffer, s string) {
	out, _ := jsontext.AppendQuote(nil, s) // minimal escaping; s is valid UTF-8 after Parse
	b.Write(out)
}

// RouteScan is lenient and is used ONLY to address an error for a rejected
// line (AC-7). It classifies the line and returns the top-level id only if
// "id" occurs exactly once at the top level with a string or number value.
func RouteScan(line []byte) (Kind, *Value) {
	d := jsontext.NewDecoder(bytes.NewReader(line), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	if t, err := d.ReadToken(); err != nil || t.Kind() != '{' {
		return Invalid, nil
	}
	var id *Value
	ids, method := 0, false
	for d.PeekKind() == '"' {
		tok, err := d.ReadToken()
		if err != nil {
			break
		}
		switch tok.String() {
		case "id":
			ids++
			id = nil
			if k := d.PeekKind(); k != '"' && k != '0' {
				break // non-scalar or unreadable id: skipped below
			}
			if t, err := d.ReadToken(); err == nil {
				id = &Value{Kind: String, Str: t.String()}
				if t.Kind() == '0' {
					id = &Value{Kind: Number, Num: t.String()}
				}
			}
			continue
		case "method":
			method = true
		}
		if d.SkipValue() != nil {
			break
		}
	}
	kind := Response
	if method {
		kind = Notification
		if ids > 0 {
			kind = Request
		}
	}
	if ids != 1 {
		id = nil
	}
	return kind, id
}
