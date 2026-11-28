package jsonrpc

import (
	"strconv"
)

// Error codes Bulwark sends (DESIGN.md §6.6).
const (
	CodeMethodNotFound     = -32601
	CodeInternal           = -32603
	CodeUnsupportedVersion = -32022
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
