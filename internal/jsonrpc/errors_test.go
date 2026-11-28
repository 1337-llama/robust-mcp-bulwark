package jsonrpc

import "testing"

// Verifies: FR-028 (DESIGN.md §6.6 error forms, exact JSON)
func TestErrorForms(t *testing.T) {
	id := &Value{Kind: Number, Num: "7"}
	cases := map[string]string{
		string(ErrorResponse(nil, CodeParse, "Parse error", nil)):                                                      `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`,
		string(ErrorResponse(id, CodeInvalid, "Invalid Request", nil)):                                                 `{"jsonrpc":"2.0","id":7,"error":{"code":-32600,"message":"Invalid Request"}}`,
		string(ErrorResponse(id, CodeLimit, "Limit exceeded", nil)):                                                    `{"jsonrpc":"2.0","id":7,"error":{"code":-32010,"message":"Limit exceeded"}}`,
		string(ErrorResponse(id, CodeMethodNotFound, "Method not found", nil)):                                         `{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"Method not found"}}`,
		string(ErrorResponse(id, CodeInternal, "upstream protocol violation", nil)):                                    `{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"upstream protocol violation"}}`,
		string(UnsupportedVersion(id, []string{"2026-07-28", "2025-11-25"})):                                           `{"jsonrpc":"2.0","id":7,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-11-25"]}}}`,
		string(BlockedToolResult(id, "Blocked by MCP Bulwark (policy:x). The call was not sent to the server.", true)): `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"Blocked by MCP Bulwark (policy:x). The call was not sent to the server."}],"isError":true,"resultType":"complete"}}`,
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
		if _, err := Parse([]byte(got), 64); err != nil {
			t.Errorf("not valid JSON-RPC: %s", got)
		}
	}
}
