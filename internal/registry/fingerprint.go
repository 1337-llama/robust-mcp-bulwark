// Package registry fingerprints tool definitions and server metadata and
// keeps the pin store (DESIGN.md §5.3; spec 003).
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/1337-llama/robust-mcp-bulwark/internal/canon"
	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

// Tool fingerprints the whole tool object as received: every field counts,
// including annotations, icons, _meta and unknown fields (AC-1). Only the
// JSON Pointers (RFC 6901) in exclude are left out.
func Tool(tool *jsonrpc.Value, exclude []string) string {
	v := tool
	for _, p := range exclude {
		v = without(v, p)
	}
	return sum(v)
}

// volatile members of a discover or initialize result change between calls
// without changing what the model sees (AC-2).
var volatile = map[string]bool{"ttlMs": true, "cacheScope": true, "resultType": true}

// Metadata fingerprints the whole server/discover (2026-07-28) or initialize
// (2025-11-25) result minus its volatile top-level members (AC-2). A missing
// member is absent, not null, so the two fingerprint differently.
func Metadata(result *jsonrpc.Value) string {
	if result == nil || result.Kind != jsonrpc.Object {
		return sum(result)
	}
	kept := *result
	kept.Members = nil
	for _, m := range result.Members {
		if !volatile[m.Name] {
			kept.Members = append(kept.Members, m)
		}
	}
	return sum(&kept)
}

func sum(v *jsonrpc.Value) string {
	if v == nil {
		v = &jsonrpc.Value{Kind: jsonrpc.Null}
	}
	h := sha256.Sum256(canon.Bytes(v))
	return "sha256:" + hex.EncodeToString(h[:])
}

// without returns a copy of v with the value at pointer removed; v itself is
// never modified. An invalid or missing pointer leaves v unchanged.
func without(v *jsonrpc.Value, pointer string) *jsonrpc.Value {
	if pointer == "" || pointer[0] != '/' || v == nil {
		return v
	}
	head, rest, _ := strings.Cut(pointer[1:], "/")
	head = strings.NewReplacer("~1", "/", "~0", "~").Replace(head)
	out := *v
	switch v.Kind {
	case jsonrpc.Object:
		out.Members = nil
		for _, m := range v.Members {
			switch {
			case m.Name != head:
				out.Members = append(out.Members, m)
			case rest != "" || strings.HasSuffix(pointer, "/"):
				out.Members = append(out.Members, jsonrpc.Member{Name: m.Name, Value: without(m.Value, "/"+rest)})
			}
		}
	case jsonrpc.Array:
		i, err := strconv.Atoi(head)
		if err != nil || i < 0 || i >= len(v.Elems) {
			return v
		}
		out.Elems = append([]*jsonrpc.Value(nil), v.Elems[:i]...)
		if rest != "" {
			out.Elems = append(out.Elems, without(v.Elems[i], "/"+rest))
		}
		out.Elems = append(out.Elems, v.Elems[i+1:]...)
	}
	return &out
}
