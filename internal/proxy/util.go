package proxy

import (
	"encoding/json"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// blockedToolResult is the tools/call result for a block (DESIGN.md §6.6):
// isError, so clients show it to the model; resultType under 2026-07-28.
func blockedToolResult(id *jsonrpc.Value, text string, modern bool) []byte {
	result := &jsonrpc.Value{Kind: jsonrpc.Object, Members: []jsonrpc.Member{
		{Name: "content", Value: &jsonrpc.Value{Kind: jsonrpc.Array, Elems: []*jsonrpc.Value{{Kind: jsonrpc.Object, Members: []jsonrpc.Member{
			{Name: "type", Value: &jsonrpc.Value{Kind: jsonrpc.String, Str: "text"}},
			{Name: "text", Value: &jsonrpc.Value{Kind: jsonrpc.String, Str: text}},
		}}}}},
		{Name: "isError", Value: &jsonrpc.Value{Kind: jsonrpc.Bool, Bool: true}},
	}}
	if modern {
		result.Members = append(result.Members, jsonrpc.Member{Name: "resultType", Value: &jsonrpc.Value{Kind: jsonrpc.String, Str: "complete"}})
	}
	return jsonrpc.Serialize(&jsonrpc.Value{Kind: jsonrpc.Object, Members: []jsonrpc.Member{
		{Name: "jsonrpc", Value: &jsonrpc.Value{Kind: jsonrpc.String, Str: "2.0"}}, {Name: "id", Value: id}, {Name: "result", Value: result},
	}})
}
