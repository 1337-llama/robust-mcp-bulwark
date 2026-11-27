// LAB ONLY: helpers for the harmless attack lab (DESIGN.md §5.9). Lab servers
// use fake canary secrets, read fixtures only inside the run directory, and
// write "exfiltrated" data only to a local observation log.
package labkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Canaries reads the run's canary set from BULWARK_LAB_CANARIES.
func Canaries() (map[string]string, error) {
	var c map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("BULWARK_LAB_CANARIES")), &c); err != nil {
		return nil, fmt.Errorf("BULWARK_LAB_CANARIES: %w", err)
	}
	if len(c) == 0 {
		return nil, errors.New("BULWARK_LAB_CANARIES: empty")
	}
	return c, nil
}

// Found returns the sorted names of the canaries that occur in s.
func Found(s string, canaries map[string]string) []string {
	var names []string
	for name, v := range canaries {
		if v != "" && strings.Contains(s, v) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Path resolves a fixture path and refuses anything outside BULWARK_LAB_DIR.
func Path(p string) (string, error) {
	dir := os.Getenv("BULWARK_LAB_DIR")
	if dir == "" || p == "" {
		return "", errors.New("labkit: BULWARK_LAB_DIR and path are required")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	rel, err := filepath.Rel(dir, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("labkit: %q is outside the lab directory", p)
	}
	return filepath.Join(dir, rel), nil
}

// Obs writes the observation log: one JSON line per event, numbered by a
// per-process counter instead of a timestamp, so runs are deterministic.
type Obs struct {
	mu     sync.Mutex
	path   string
	server string
	seq    int
}

func NewObs(path, server string) *Obs { return &Obs{path: path, server: server} }

type record struct {
	Seq      int      `json:"seq"`
	Server   string   `json:"server"`
	Event    string   `json:"event"`
	Tool     string   `json:"tool"`
	Canaries []string `json:"canaries"`
}

// Record appends an event: "call", "exfil", or "forbidden".
func (o *Obs) Record(event, tool string, canaries []string) error {
	switch event {
	case "call", "exfil", "forbidden":
	default:
		return fmt.Errorf("labkit: unknown event %q", event)
	}
	if canaries == nil {
		canaries = []string{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seq++
	line, err := json.Marshal(record{o.seq, o.server, event, tool, canaries})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(o.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
