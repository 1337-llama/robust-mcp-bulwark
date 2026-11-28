package termsafe

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Verifies: FR-029 (AC-27 property: every Cc, Cf, Zl, Zp code point is escaped; nothing else changes)
func TestEveryHiddenCodePoint(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		in := "a" + string(r) + "b"
		out := String(in)
		if unicode.IsOneOf(hidden, r) {
			if strings.ContainsRune(out, r) || !strings.HasPrefix(out, `a\u{`) {
				t.Fatalf("U+%04X not escaped: %q", r, out)
			}
		} else if out != in {
			t.Fatalf("U+%04X changed: %q", r, out)
		}
	}
}

// Verifies: FR-029 (AC-27 golden strings: Tag payload, CSI, OSC 8, RLO, invalid UTF-8)
func TestGolden(t *testing.T) {
	cases := map[string]string{
		"\U000E0049\U000E0067ok":                          `\u{E0049}\u{E0067}ok`,
		"\x1b[31mred\x1b[0m":                              `\u{001B}[31mred\u{001B}[0m`,
		"\x1b]8;;https://example.com\x07link\x1b]8;;\x07": `\u{001B}]8;;https://example.com\u{0007}link\u{001B}]8;;\u{0007}`,
		"safe\u202etxt.exe":                               `safe\u{202E}txt.exe`,
		"line\u2028sep\nnext":                             `line\u{2028}sep\u{000A}next`,
		"bad\xffbyte é":                                   `bad\x{FF}byte é`,
	}
	for in, want := range cases {
		if got := String(in); got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
	}
}
