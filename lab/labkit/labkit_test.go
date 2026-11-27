// LAB ONLY: test helpers for the harmless attack lab. See DESIGN.md §5.9.
package labkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verifies: FR-002
func TestCanaries(t *testing.T) {
	t.Setenv("BULWARK_LAB_CANARIES", `{"plain":"canary-plain-l04","secret":"AKIAEXAMPLECANARYLDZ"}`)
	c, err := Canaries()
	if err != nil || c["plain"] != "canary-plain-l04" || c["secret"] != "AKIAEXAMPLECANARYLDZ" {
		t.Fatalf("got %v, %v", c, err)
	}
	for _, bad := range []string{"", "not json", `{"plain":1}`, `{}`} {
		t.Setenv("BULWARK_LAB_CANARIES", bad)
		if _, err := Canaries(); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Verifies: FR-002
func TestFound(t *testing.T) {
	c := map[string]string{"plain": "canary-plain-l04", "secret": "AKIAEXAMPLECANARYLDZ"}
	got := Found("x AKIAEXAMPLECANARYLDZ y canary-plain-l04", c)
	if strings.Join(got, ",") != "plain,secret" {
		t.Fatalf("got %v", got)
	}
	if Found("nothing here", c) != nil {
		t.Fatal("false match")
	}
}

// Verifies: FR-002 (AC-3: fixtures confined to the run directory)
func TestPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BULWARK_LAB_DIR", dir)
	p, err := Path("private/secret.txt")
	if err != nil || p != filepath.Join(dir, "private", "secret.txt") {
		t.Fatalf("got %q, %v", p, err)
	}
	if p, err := Path(filepath.Join(dir, "workspace", "a")); err != nil || p != filepath.Join(dir, "workspace", "a") {
		t.Fatalf("absolute inside: %q, %v", p, err)
	}
	for _, bad := range []string{"../x", "workspace/../../x", "/etc/passwd", ""} {
		if _, err := Path(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	t.Setenv("BULWARK_LAB_DIR", "")
	if _, err := Path("a"); err == nil {
		t.Error("accepted unset BULWARK_LAB_DIR")
	}
}

// Verifies: FR-002 (AC-9: deterministic seq counter, no timestamps)
func TestObs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs.jsonl")
	o := NewObs(path, "l04-web-notes")
	if err := o.Record("call", "fetch_note", nil); err != nil {
		t.Fatal(err)
	}
	if err := o.Record("exfil", "http_post", []string{"plain"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	want := `{"seq":1,"server":"l04-web-notes","event":"call","tool":"fetch_note","canaries":[]}
{"seq":2,"server":"l04-web-notes","event":"exfil","tool":"http_post","canaries":["plain"]}
`
	if string(b) != want {
		t.Fatalf("got\n%s", b)
	}
	if err := o.Record("bogus", "x", nil); err == nil {
		t.Error("accepted unknown event")
	}
}
