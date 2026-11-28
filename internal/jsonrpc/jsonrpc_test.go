package jsonrpc

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/go-json-experiment/json/jsontext"
)

func code(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

// Verifies: FR-028 (T1: the strict defaults the gateway relies on)
func TestJSONTextDefaults(t *testing.T) {
	for _, bad := range []string{`{"a":1,"a":2}`, "{\"a\":\"\xff\"}", `{"a":"\ud800"}`} {
		d := jsontext.NewDecoder(strings.NewReader(bad))
		if _, err := d.ReadValue(); err == nil {
			t.Errorf("jsontext accepted %q with default options", bad)
		}
	}
	for _, lit := range []string{"12345678901234567890123", "1.50e+10", "-0", "1e400"} {
		tok, err := jsontext.NewDecoder(strings.NewReader(lit)).ReadToken()
		if err != nil || tok.String() != lit {
			t.Errorf("number literal %s came back as %q (%v)", lit, tok.String(), err)
		}
	}
}

// Verifies: NFR-013 (AC-10: byte cap, discard to newline, next line still read)
func TestReadLine(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("abcd\nabcde\nxy\r\nwxyz\r\nlast\nabcde"), 16)
	for _, want := range []string{"abcd", "!", "xy", "wxyz", "last", "!"} {
		got, err := ReadLine(r, 4)
		if want == "!" {
			if err != ErrTooLong {
				t.Fatalf("over-long line: %v", err)
			}
			continue
		}
		if err != nil || string(got) != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	long := strings.Repeat("x", 100) + "\nok\n"
	r = bufio.NewReaderSize(strings.NewReader(long), 16)
	if _, err := ReadLine(r, 10); err != ErrTooLong {
		t.Fatal(err)
	}
	if got, _ := ReadLine(r, 10); string(got) != "ok" {
		t.Fatalf("after discard got %q", got)
	}
}

// Verifies: FR-028 (AC-7a, AC-7b, classification)
func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		code int
		kind Kind
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, 0, Request},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, 0, Notification},
		{`{"jsonrpc":"2.0","id":"a","result":{}}`, 0, Response},
		{`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`, 0, Response},
		{`{"jsonrpc":"2.0","id":1,`, CodeParse, 0},
		{`not json`, CodeParse, 0},
		{`{"jsonrpc":"2.0","id":1,"id":2,"method":"x"}`, CodeInvalid, 0},
		{"{\"jsonrpc\":\"2.0\",\"method\":\"\xff\"}", CodeInvalid, 0},
		{`{"jsonrpc":"2.0","method":"x","params":{"s":"\udc00"}}`, CodeInvalid, 0},
		{`[{"jsonrpc":"2.0","method":"x"}]`, CodeInvalid, 0},
		{`{"jsonrpc":"1.0","method":"x"}`, CodeInvalid, 0},
		{`{"jsonrpc":"2.0","id":{},"method":"x"}`, CodeInvalid, 0},
		{`{"jsonrpc":"2.0","id":1,"result":1,"error":{}}`, CodeInvalid, 0},
		{`{"jsonrpc":"2.0","method":"x","params":[[[[1]]]]}`, CodeLimit, 0}, // depth 5 > 4: AC-10
		{`{"jsonrpc":"2.0","id":null,"method":"x"}`, CodeInvalid, 0},
		{`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}`, 0, Response},
	}
	for _, c := range cases {
		m, err := Parse([]byte(c.in), 4)
		if code(err) != c.code || (err == nil && m.Kind != c.kind) {
			t.Errorf("%s: code %d (%v), kind %v", c.in, code(err), err, m)
		}
	}
}

// Verifies: FR-028 (AC-7 routing scan)
func TestRouteScan(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
		id   string
	}{
		{`{"jsonrpc":"2.0","id":7,"method":"x","params":{"id":9}}`, Request, "7"},
		{`{"id":"abc","result":{}}`, Response, "abc"},
		{`{"id":1,"id":2,"method":"x"}`, Request, ""},
		{`{"method":"x"}`, Notification, ""},
		{`{"id":{"a":1},"method":"x"}`, Request, ""},
		{`{"id":5,"method":"x","params":{"a":`, Request, "5"},
		{`[1]`, Invalid, ""},
		{"{\"id\":\"a\xffb\",\"method\":\"x\"}", Request, ""},
	}
	for _, c := range cases {
		kind, id := RouteScan([]byte(c.in))
		got := ""
		if id != nil {
			got = id.Str + id.Num
		}
		if kind != c.kind || got != c.id {
			t.Errorf("%s: kind %v id %q", c.in, kind, got)
		}
	}
}

// Verifies: FR-028 (AC-2, AC-8, AC-9 round trip, exact literals, order, unknown fields)
func TestRoundTrip(t *testing.T) {
	for _, in := range []string{
		`{"jsonrpc":"2.0","id":12345678901234567890123,"method":"m","params":{"z":1.50e+10,"a":-0,"u":{"x":[true,false,null]},"s":"<&>\u2028é"}}`,
		`{"jsonrpc":"2.0","result":{"b":2,"a":1},"id":"x"}`,
	} {
		m, err := Parse([]byte(in), 64)
		if err != nil {
			t.Fatal(err)
		}
		out := Serialize(m.Root)
		m2, err := Parse(out, 64)
		if err != nil || !reflect.DeepEqual(m.Root, m2.Root) {
			t.Fatalf("round trip: %s -> %s (%v)", in, out, err)
		}
		for _, lit := range []string{"12345678901234567890123", "1.50e+10", "-0", `"z"`} {
			if strings.Contains(in, lit) && !strings.Contains(string(out), lit) {
				t.Errorf("lost %s in %s", lit, out)
			}
		}
		if strings.Index(string(out), `"b"`) > strings.Index(string(out), `"a"`) && strings.Contains(in, `"b":2,"a":1`) {
			t.Error("member order changed")
		}
	}
}

// Verifies: FR-028 (AC-9 fuzz: no panic; accepted input round-trips)
func FuzzParseSerialize(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"n":1e400}}}`)
	f.Add(`{"jsonrpc":"2.0","id":"a","result":{"k":[1,2,{"x":null}]}}`)
	f.Fuzz(func(t *testing.T, s string) {
		m, err := Parse([]byte(s), 64)
		RouteScan([]byte(s))
		if err != nil {
			return
		}
		out := Serialize(m.Root)
		m2, err := Parse(out, 64)
		if err != nil || !reflect.DeepEqual(m.Root, m2.Root) {
			t.Fatalf("accepted input did not round-trip: %q -> %q", s, out)
		}
	})
}

// gen builds a random JSON value text: big integers, exponent literals,
// unicode strings, nesting, and arbitrary (unknown) member names.
func gen(r *rand.Rand, depth int) string {
	switch k := r.IntN(7); {
	case depth > 3 || k == 0:
		return []string{"12345678901234567890123", "1.50e+10", "-0", "0.1", "-7e-3", "42"}[r.IntN(6)]
	case k == 1:
		return []string{`"x"`, `"\u00e9\u2028<&>"`, `"\ud83d\ude00"`, `""`}[r.IntN(4)]
	case k == 2:
		return []string{"true", "false", "null"}[r.IntN(3)]
	case k == 3:
		return "[" + gen(r, depth+1) + "," + gen(r, depth+1) + "]"
	default:
		return fmt.Sprintf(`{"u%d":%s,"a":%s}`, r.IntN(100), gen(r, depth+1), gen(r, depth+1))
	}
}

// Verifies: FR-028 (AC-9 property test over generated messages)
func TestRoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 2000; i++ {
		in := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"m","params":%s,"x-unknown":%s}`, i, gen(r, 0), gen(r, 0))
		m, err := Parse([]byte(in), 64)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		m2, err := Parse(Serialize(m.Root), 64)
		if err != nil || !reflect.DeepEqual(m.Root, m2.Root) {
			t.Fatalf("not identical after round trip: %s", in)
		}
	}
}
