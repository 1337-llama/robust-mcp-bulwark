// Package termsafe neutralizes untrusted text before it reaches a terminal
// (FR-029, T-11; spec 002 AC-27). Every code point in Unicode categories Cc,
// Cf, Zl, and Zp is shown visibly as \u{XXXX}, so no escape sequence, bidi
// override, zero-width or Tag character survives. Invalid UTF-8 bytes are
// shown as \x{XX}.
package termsafe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var hidden = []*unicode.RangeTable{unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp}

// String returns s with every hidden or control code point escaped.
func String(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02X}`, s[i])
		case unicode.IsOneOf(hidden, r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
