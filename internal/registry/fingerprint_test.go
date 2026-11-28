package registry

import (
	"strconv"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

func val(t *testing.T, s string) *jsonrpc.Value {
	v, err := jsonrpc.ParseValue([]byte(s), 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

const tool = `{"name":"read_file","description":"Reads a file.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]},"annotations":{"readOnlyHint":true},"icons":[{"src":"https://example.com/i.png"}],"_meta":{"x":1},"unknown":null}`

// leaves returns a pointer to every leaf of v.
func leaves(v *jsonrpc.Value, at string) []string {
	switch v.Kind {
	case jsonrpc.Object:
		var out []string
		for _, m := range v.Members {
			out = append(out, leaves(m.Value, at+"/"+m.Name)...)
		}
		return out
	case jsonrpc.Array:
		var out []string
		for i, e := range v.Elems {
			out = append(out, leaves(e, at+"/"+itoa(i))...)
		}
		return out
	}
	return []string{at}
}

func itoa(i int) string { return strconv.Itoa(i) }

// set replaces the leaf at pointer with a different value.
func set(v *jsonrpc.Value, pointer string) {
	for _, m := range v.Members {
		if "/"+m.Name == pointer {
			m.Value.Kind, m.Value.Str = jsonrpc.String, "MUTATED"
			return
		}
		if len(pointer) > len(m.Name)+1 && pointer[:len(m.Name)+2] == "/"+m.Name+"/" {
			set(m.Value, pointer[len(m.Name)+1:])
			return
		}
	}
	for i, e := range v.Elems {
		if pointer == "/"+itoa(i) {
			e.Kind, e.Str = jsonrpc.String, "MUTATED"
			return
		}
		if prefix := "/" + itoa(i) + "/"; len(pointer) > len(prefix) && pointer[:len(prefix)] == prefix {
			set(e, pointer[len(prefix)-1:])
			return
		}
	}
}

// Verifies: FR-021 (AC-1: every leaf counts, including icons, _meta and unknown fields; exclude_fields)
func TestToolFingerprint(t *testing.T) {
	base := Tool(val(t, tool), nil)
	if base != "sha256:"+base[7:] || len(base) != 71 {
		t.Fatalf("format %q", base)
	}
	ls := leaves(val(t, tool), "")
	if len(ls) < 8 {
		t.Fatalf("only %d leaves", len(ls))
	}
	for _, p := range ls {
		v := val(t, tool)
		set(v, p)
		if Tool(v, nil) == base {
			t.Errorf("mutating %s did not change the fingerprint", p)
		}
	}
	reordered := `{"description":"Reads a file.","name":"read_file","inputSchema":{"required":["path"],"type":"object","properties":{"path":{"type":"string"}}},"annotations":{"readOnlyHint":true},"icons":[{"src":"https://example.com/i.png"}],"_meta":{"x":1},"unknown":null}`
	if Tool(val(t, reordered), nil) != base {
		t.Error("member order must not matter")
	}
	noisy := val(t, tool)
	set(noisy, "/_meta/x")
	if Tool(noisy, []string{"/_meta/x"}) != Tool(val(t, tool), []string{"/_meta/x"}) || Tool(val(t, tool), []string{"/_meta/x"}) == base {
		t.Error("exclude_fields must remove exactly the named field")
	}
}

// Verifies: FR-033 (AC-2: whole metadata result, volatile members ignored, absent != null, unknown _meta counts)
func TestMetadataFingerprint(t *testing.T) {
	a := `{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"instructions":"x","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"s","version":"1"}}`
	base := Metadata(val(t, a+`,"ttlMs":1000,"cacheScope":"session","resultType":"complete"}`))
	if Metadata(val(t, a+`,"ttlMs":5}`)) != base {
		t.Error("volatile members must be ignored")
	}
	if Metadata(val(t, a+`,"extra":null}`)) == base {
		t.Error("an explicit null differs from absent")
	}
	if Metadata(val(t, `{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"instructions":"x","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"s","version":"1"},"other":1}}`)) == base {
		t.Error("unknown _meta keys count")
	}
}
