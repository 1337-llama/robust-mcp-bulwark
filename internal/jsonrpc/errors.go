package jsonrpc

import (
	"strconv"
)

// Error codes Bulwark sends (DESIGN.md §6.6).
const (
	CodeMethodNotFound     = -32601
	CodeInternal           = -32603
	CodeUnsupportedVersion = -32022
	CodeBlocked            = -32011
)

// ErrorResponse builds a JSON-RPC error response. A nil id becomes "id": null
// (JSON-RPC 2.0 §5). data, if non-nil, is attached as "data".
func ErrorResponse(id *Value, code int, msg string, data *Value) []byte {
	if id == nil {
		id = &Value{Kind: Null}
	}
	e := &Value{Kind: Object, Members: []Member{
		{"code", &Value{Kind: Number, Num: strconv.Itoa(code)}},
		{"message", &Value{Kind: String, Str: msg}},
	}}
	if data != nil {
		e.Members = append(e.Members, Member{"data", data})
	}
	return Serialize(&Value{Kind: Object, Members: []Member{
		{"jsonrpc", &Value{Kind: String, Str: "2.0"}}, {"id", id}, {"error", e},
	}})
}

// UnsupportedVersion is the -32022 error listing the supported revisions.
func UnsupportedVersion(id *Value, supported []string) []byte {
	list := &Value{Kind: Array}
	for _, s := range supported {
		list.Elems = append(list.Elems, &Value{Kind: String, Str: s})
	}
	return ErrorResponse(id, CodeUnsupportedVersion, "Unsupported protocol version",
		&Value{Kind: Object, Members: []Member{{"supported", list}}})
}

// BlockedToolResult is the tools/call result a policy, secret or MRTR block
// returns (isError, so clients show it to the model). modern adds the
// 2026-07-28 resultType.
func BlockedToolResult(id *Value, text string, modern bool) []byte {
	result := &Value{Kind: Object, Members: []Member{
		{"content", &Value{Kind: Array, Elems: []*Value{{Kind: Object, Members: []Member{
			{"type", &Value{Kind: String, Str: "text"}},
			{"text", &Value{Kind: String, Str: text}},
		}}}}},
		{"isError", &Value{Kind: Bool, Bool: true}},
	}}
	if modern {
		result.Members = append(result.Members, Member{"resultType", &Value{Kind: String, Str: "complete"}})
	}
	return Serialize(&Value{Kind: Object, Members: []Member{
		{"jsonrpc", &Value{Kind: String, Str: "2.0"}}, {"id", id}, {"result", result},
	}})
}
