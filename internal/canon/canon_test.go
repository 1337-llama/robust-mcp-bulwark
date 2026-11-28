package canon

import (
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

func canon(t *testing.T, s string) string {
	m, err := jsonrpc.Parse([]byte(`{"jsonrpc":"2.0","method":"x","params":`+s+`}`), 64)
	if err != nil {
		t.Fatal(err)
	}
	return string(Bytes(m.Root.Get("params")))
}

// Verifies: FR-026, FR-021 (canonical form: RFC 8785 order and escaping, exact numbers)
func TestCanon(t *testing.T) {
	cases := map[string]string{
		// RFC 8785 §3.2.3 example ordering: UTF-16 code units, so U+1F600 (surrogates D83D…) sorts before U+FB33.
		`{"\u20ac":1,"\r":2,"1":3,"\ud83d\ude00":4,"\u00f6":5,"\ufb33":6,"\u0080":7}`: "{\"\\r\":2,\"1\":3,\"\u0080\":7,\"\u00f6\":5,\"\u20ac\":1,\"\U0001F600\":4,\"\ufb33\":6}",
		`{"b":[1.50e+10,-0,12345678901234567890123],"a":{"y":null,"x":true}}`:         `{"a":{"x":true,"y":null},"b":[1.50e+10,-0,12345678901234567890123]}`,
		`{"s":"tab\there \u0001 quote\" slash\\ \u2028 é"}`:                           "{\"s\":\"tab\\there \\u0001 quote\\\" slash\\\\ \u2028 é\"}",
	}
	for in, want := range cases {
		if got := canon(t, in); got != want {
			t.Errorf("%s\n got %s\nwant %s", in, got, want)
		}
	}
	if canon(t, `{"a":1,"b":2}`) != canon(t, `{"b":2,"a":1}`) {
		t.Error("member order must not matter")
	}
	if canon(t, `{"n":1.0}`) == canon(t, `{"n":1}`) {
		t.Error("different number literals must stay different")
	}
}
