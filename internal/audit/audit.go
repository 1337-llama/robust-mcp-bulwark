// Package audit writes and verifies the hash-chained audit log (DESIGN.md
// §5.8, §6.5; spec 002 AC-20 to AC-25). Each record's hash is
// SHA-256(prev_hash ‖ canonical record without "hash"), so modifying,
// inserting, deleting or reordering a record breaks the chain. Truncating the
// tail or rewriting a whole file needs an external anchor to detect (AR-6).
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/canon"
	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

// Genesis is the prev_hash of a file's first record.
const Genesis = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Record is the audit record of DESIGN.md §6.5. Omitted fields stay out of the JSON.
type Record struct {
	V         int               `json:"v"`
	Seq       int               `json:"seq"`
	TS        string            `json:"ts"`
	Event     string            `json:"event"`
	ServerID  string            `json:"server_id,omitempty"`
	Revision  string            `json:"revision,omitempty"`
	Direction string            `json:"direction,omitempty"`
	Method    string            `json:"method,omitempty"`
	Tool      string            `json:"tool,omitempty"`
	JSONRPCID json.RawMessage   `json:"jsonrpc_id,omitempty"`
	ArgsMAC   string            `json:"args_mac,omitempty"`
	ArgsBytes int               `json:"args_bytes,omitempty"`
	Decision  string            `json:"decision,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Controls  []string          `json:"controls,omitempty"`
	Findings  []json.RawMessage `json:"findings,omitempty"`
	Detail    map[string]any    `json:"detail,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash,omitempty"`
}

// Writer appends records to one chain file. It is safe for concurrent use.
type Writer struct {
	mu     sync.Mutex
	f      *os.File
	key    []byte
	prev   string
	seq    int
	now    func() time.Time
	synced bool
	timer  *time.Timer
	err    error // first failed fsync; returned by the next Write and by Close
}

// Open creates <dir>/<UTC start>-<pid>.jsonl and loads (or creates, mode
// 0600) the HMAC key at keyPath.
func Open(dir, keyPath string, now func() time.Time) (*Writer, error) {
	key, err := loadKey(keyPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%s-%d.jsonl", now().UTC().Format("20060102T150405Z"), os.Getpid())
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, key: key, prev: Genesis, now: now, synced: true}, nil
}

// loadKey reads the per-install HMAC key, creating it on first use. The new
// key is written to a temp file and linked into place, so two processes
// starting at once never see a half-written key.
func loadKey(path string) ([]byte, error) {
	read := func() ([]byte, error) {
		b, err := os.ReadFile(path)
		if err == nil && len(b) != 32 {
			err = fmt.Errorf("audit key %s: want 32 bytes", path)
		}
		if err == nil {
			if fi, serr := os.Stat(path); serr == nil && fi.Mode().Perm() != 0o600 {
				fmt.Fprintf(os.Stderr, "bulwark: warning: %s has mode %v, want 0600\n", path, fi.Mode().Perm())
			}
		}
		return b, err
	}
	if b, err := read(); err == nil || !errors.Is(err, os.ErrNotExist) {
		return b, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".audit.key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(key); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return read() // another process won the race
		}
		return nil, err
	}
	return key, nil
}

// MAC returns the keyed argument digest stored instead of raw arguments.
func (w *Writer) MAC(args []byte) string {
	m := hmac.New(sha256.New, w.key)
	m.Write(args)
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
}

// Write completes, chains and appends r in a single write call. An error means
// the record was not written; in enforce mode the caller must fail closed (AC-24).
func (w *Writer) Write(r Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	r.V, r.Seq, r.PrevHash, r.Hash = 1, w.seq+1, w.prev, ""
	r.TS = w.now().UTC().Format("2006-01-02T15:04:05.000Z")
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	h, err := hashOf(body)
	if err != nil {
		return err
	}
	r.Hash = h
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		return err
	}
	w.prev, w.seq = h, w.seq+1 // only after a successful write, so a failure leaves no hole
	if w.synced {              // fsync within a second of the first unsynced record (AC-25)
		w.synced = false
		w.timer = time.AfterFunc(time.Second, w.sync)
	}
	return nil
}

func (w *Writer) sync() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.f.Sync(); err != nil && w.err == nil {
		w.err = fmt.Errorf("audit fsync: %w", err)
	}
	w.synced = true
}

// Close syncs and closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
	}
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if w.err != nil {
		return w.err
	}
	return err
}

// hashOf hashes prev_hash ‖ canonical form of the record bytes without "hash".
// Working on the bytes (not a re-marshalled struct) keeps verification exact.
func hashOf(line []byte) (string, error) {
	v, err := jsonrpc.ParseValue(line, 64)
	if err != nil || v.Kind != jsonrpc.Object {
		return "", errors.New("not a JSON object")
	}
	prev := v.Get("prev_hash")
	if prev == nil || prev.Kind != jsonrpc.String {
		return "", errors.New("missing prev_hash")
	}
	kept := *v
	kept.Members = nil
	for _, m := range v.Members {
		if m.Name != "hash" {
			kept.Members = append(kept.Members, m)
		}
	}
	sum := sha256.Sum256(append([]byte(prev.Str), canon.Bytes(&kept)...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ErrBroken reports the first record that does not verify.
type ErrBroken struct {
	Line   int
	Reason string
}

func (e *ErrBroken) Error() string { return fmt.Sprintf("record on line %d: %s", e.Line, e.Reason) }

// Limit is printed by `audit verify` after every result (AR-6).
const Limit = "note: a truncated tail or a wholly rewritten file cannot be detected without an external anchor (AR-6)"

// Verify recomputes the chain of one file. It returns the number of records,
// or an *ErrBroken naming the first bad record.
func Verify(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 16<<20)
	prev, n := Genesis, 0
	for sc.Scan() {
		n++
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return n - 1, &ErrBroken{n, "not a valid record"}
		}
		if rec.Seq != n {
			return n - 1, &ErrBroken{n, fmt.Sprintf("seq %d, want %d (record inserted, deleted or reordered)", rec.Seq, n)}
		}
		if rec.PrevHash != prev {
			return n - 1, &ErrBroken{n, "prev_hash does not match the previous record"}
		}
		h, err := hashOf(sc.Bytes())
		if err != nil || h != rec.Hash {
			return n - 1, &ErrBroken{n, "hash mismatch (record modified)"}
		}
		prev = rec.Hash
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if n == 0 {
		return 0, errors.New("empty audit file")
	}
	return n, nil
}
