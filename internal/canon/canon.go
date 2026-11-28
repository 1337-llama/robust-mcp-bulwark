// Package canon writes the canonical form of a JSON value (DESIGN.md §5.3):
// RFC 8785 (JCS) member order and string rules, but number literals are kept
// exactly as received, so two different literals never hash the same.
package canon

import (
	"bytes"
	"fmt"
	"slices"
	"unicode/utf16"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

// Bytes returns the canonical form of v.
func Bytes(v *jsonrpc.Value) []byte {
	var b bytes.Buffer
	write(&b, v)
	return b.Bytes()
}

func write(b *bytes.Buffer, v *jsonrpc.Value) {
	switch v.Kind {
	case jsonrpc.Object:
		// RFC 8785 §3.2.3: sort member names by their UTF-16 code units (encoded once each).
		type keyed struct {
			key []uint16
			m   jsonrpc.Member
		}
		ks := make([]keyed, len(v.Members))
		for i, m := range v.Members {
			ks[i] = keyed{utf16.Encode([]rune(m.Name)), m}
		}
		slices.SortFunc(ks, func(x, y keyed) int { return slices.Compare(x.key, y.key) })
		ms := make([]jsonrpc.Member, len(ks))
		for i, k := range ks {
			ms[i] = k.m
		}
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteByte(',')
			}
			str(b, m.Name)
			b.WriteByte(':')
			write(b, m.Value)
		}
		b.WriteByte('}')
	case jsonrpc.Array:
		b.WriteByte('[')
		for i, e := range v.Elems {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, e)
		}
		b.WriteByte(']')
	case jsonrpc.String:
		str(b, v.Str)
	case jsonrpc.Number:
		b.WriteString(v.Num) // exact literal (decision: no number normalization)
	case jsonrpc.Bool:
		fmt.Fprint(b, v.Bool)
	case jsonrpc.Null:
		b.WriteString("null")
	}
}

// str applies RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify) string escaping.
func str(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
