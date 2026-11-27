// LAB ONLY: strict loader and validator for attack-scenario manifests
// (spec 001 AC-1, AC-2, AC-8, AC-28; format in specs/001-attack-suite/plan.md).
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Manifest struct {
	ID         string              `yaml:"id"`
	Title      string              `yaml:"title"`
	References []string            `yaml:"references"`
	Technique  map[string][]string `yaml:"technique"`
	Server     string              `yaml:"server"`
	Revisions  []string            `yaml:"revisions"`
	Canaries   map[string]string   `yaml:"canaries"`
	Script     []Step              `yaml:"script"`
	Runs       []Run               `yaml:"runs"`
}

// Step is one replay action; exactly one field is set.
type Step struct {
	Discover         *struct{}        `yaml:"discover"`
	ListTools        *struct{}        `yaml:"list_tools"`
	Call             *Call            `yaml:"call"`
	Subscribe        *map[string]bool `yaml:"subscribe"`
	WaitNotification *struct {
		Method string `yaml:"method"`
	} `yaml:"wait_notification"`
	SendRaw *struct {
		Line string `yaml:"line"`
	} `yaml:"send_raw"`
}

type Call struct {
	Name                     string         `yaml:"name"`
	Arguments                map[string]any `yaml:"arguments"`
	InputResponses           map[string]any `yaml:"input_responses"`
	RequestStateFromPrevious bool           `yaml:"request_state_from_previous"`
}

type Run struct {
	Control  string                    `yaml:"control"`
	Pending  string                    `yaml:"pending"`
	KnownGap string                    `yaml:"known_gap"`
	Setup    Setup                     `yaml:"setup"`
	Expect   map[string]map[string]any `yaml:"expect"`
}

type Setup struct {
	Approve         Approve                      `yaml:"approve"`
	ApproveMetadata *bool                        `yaml:"approve_metadata"`
	ArgRoles        map[string]map[string]string `yaml:"arg_roles"`
	Policy          string                       `yaml:"policy"`
}

// Approve is "all" (the default), "none", or a list of tool names.
type Approve struct {
	None  bool
	Tools []string // nil with None false means all
}

func (a *Approve) UnmarshalYAML(n *yaml.Node) error {
	switch {
	case n.Kind == yaml.ScalarNode && n.Value == "all":
	case n.Kind == yaml.ScalarNode && n.Value == "none":
		a.None = true
	case n.Kind == yaml.SequenceNode:
		return n.Decode(&a.Tools)
	default:
		return fmt.Errorf("line %d: approve must be all, none, or a list of tool names", n.Line)
	}
	return nil
}

func (a Approve) approves(tool string) bool {
	return !a.None && (a.Tools == nil || slices.Contains(a.Tools, tool))
}

// Allowlist is lab/scenarios/allowlist.yaml.
type Allowlist struct {
	Techniques map[string][]string `yaml:"techniques"`
	Controls   struct {
		Exact     []string `yaml:"exact"`
		Analyzers []string `yaml:"analyzers"`
		Secrets   []string `yaml:"secrets"`
	} `yaml:"controls"`
}

func decodeStrict(b []byte, v any) error {
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("only one YAML document is allowed")
	}
	return nil
}

func LoadAllowlist(path string) (*Allowlist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a Allowlist
	return &a, decodeStrict(b, &a)
}

// Load reads and validates one manifest.
func Load(path string, allow *Allowlist) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := decodeStrict(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := m.validate(allow); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

var (
	idRe      = regexp.MustCompile(`^L-0[1-8]$`) // v0.1 has eight scenarios; widen deliberately (and the AC-31 canary letters) for L-09+
	pendingRe = regexp.MustCompile(`^spec-\d{3}$`)
	policyRe  = regexp.MustCompile(`^policy:[a-z0-9][a-z0-9-]*$`)
	observ    = []string{"poison_delivered", "canary_exfiltrated", "forbidden_call_executed", "controls_fired"}
	revisions = []string{"2026-07-28", "2025-11-25"}
)

// ValidControl reports whether id is in the control vocabulary (AC-2).
func (a *Allowlist) ValidControl(id string) bool {
	if slices.Contains(a.Controls.Exact, id) || policyRe.MatchString(id) {
		return true
	}
	if rule, ok := strings.CutPrefix(id, "secrets:"); ok {
		return slices.Contains(a.Controls.Secrets, rule)
	}
	if rest, ok := strings.CutPrefix(id, "analyzer:"); ok {
		name, rule, ok := strings.Cut(rest, "/")
		return ok && rule != "" && slices.Contains(a.Controls.Analyzers, name)
	}
	return false
}

func (m *Manifest) validate(a *Allowlist) error {
	var errs []error
	bad := func(f string, args ...any) { errs = append(errs, fmt.Errorf(f, args...)) }
	if !idRe.MatchString(m.ID) {
		bad("id %q is not L-01…L-08", m.ID)
	}
	if m.Title == "" || m.Server == "" {
		bad("title and server are required")
	}
	if !slices.ContainsFunc(m.References, func(r string) bool { return strings.HasPrefix(r, "https://") }) {
		bad("at least one https:// public reference is required (AC-8)")
	}
	n := 0
	for kind, ids := range m.Technique {
		for _, id := range ids {
			n++
			if !slices.Contains(a.Techniques[kind], id) {
				bad("technique %s %q is not in the allowlist", kind, id)
			}
		}
	}
	if n == 0 {
		bad("at least one technique mapping is required")
	}
	// AC-31: secret canaries are AKIAEXAMPLECANARYL<letter>Z (A = L-01 … H = L-08),
	// all in the AWS key alphabet; plain canaries are canary-plain-l0N.
	if idRe.MatchString(m.ID) {
		k := m.ID[3] - '1'
		if s, ok := m.Canaries["secret"]; ok && s != "AKIAEXAMPLECANARYL"+string(rune('A'+k))+"Z" {
			bad("secret canary %q must be AKIAEXAMPLECANARYL%cZ (AC-31)", s, 'A'+k)
		}
		if p, ok := m.Canaries["plain"]; ok && p != "canary-plain-l0"+string(m.ID[3]) {
			bad("plain canary %q must be canary-plain-l0%c", p, m.ID[3])
		}
	}
	for name := range m.Canaries {
		if name != "plain" && name != "secret" {
			bad("unknown canary %q", name)
		}
	}
	if len(m.Revisions) == 0 {
		bad("revisions are required")
	}
	for _, r := range m.Revisions {
		if !slices.Contains(revisions, r) {
			bad("unknown revision %q", r)
		}
	}
	var called []string
	for i, s := range m.Script {
		set := 0
		for _, p := range []bool{s.Discover != nil, s.ListTools != nil, s.Call != nil, s.Subscribe != nil, s.WaitNotification != nil, s.SendRaw != nil} {
			if p {
				set++
			}
		}
		if set != 1 {
			bad("script step %d must have exactly one action", i+1)
		}
		if s.Call != nil {
			if s.Call.Name == "" {
				bad("script step %d: call needs a name", i+1)
			}
			called = append(called, s.Call.Name)
		}
	}
	if len(m.Script) == 0 || len(m.Runs) == 0 {
		bad("script and runs are required")
	}
	for i, r := range m.Runs {
		where := fmt.Sprintf("run %d (%s)", i+1, r.Control)
		if !a.ValidControl(r.Control) {
			bad("%s: control is not in the vocabulary", where)
		}
		if r.Pending != "" && !pendingRe.MatchString(r.Pending) {
			bad("%s: pending must be spec-NNN", where)
		}
		for _, cond := range []string{"none", "warn", "enforce"} {
			if _, ok := r.Expect[cond]; !ok {
				bad("%s: expect.%s is required", where, cond)
			}
		}
		for cond, obs := range r.Expect {
			if !slices.Contains([]string{"none", "warn", "enforce"}, cond) {
				bad("%s: unknown condition %q", where, cond)
			}
			for k, val := range obs {
				switch {
				case !slices.Contains(observ, k):
					bad("%s: unknown observable %q", where, k)
				case k == "controls_fired":
					list, ok := val.([]any)
					if !ok {
						bad("%s: controls_fired must be a list", where)
					}
					for _, c := range list {
						if s, ok := c.(string); !ok || !a.ValidControl(s) {
							bad("%s: controls_fired %v is not in the vocabulary", where, c)
						}
					}
				default:
					if _, ok := val.(bool); !ok {
						bad("%s: %s must be true or false", where, k)
					}
				}
			}
		}
		// AC-28: outside pin runs, pinning must not be what blocks the attack.
		if !strings.HasPrefix(r.Control, "pin:") {
			if r.Setup.ApproveMetadata != nil && !*r.Setup.ApproveMetadata {
				bad("%s: a non-pin run must approve the metadata", where)
			}
			for _, t := range called {
				if !r.Setup.Approve.approves(t) {
					bad("%s: a non-pin run must approve called tool %q", where, t)
				}
			}
		}
	}
	return errors.Join(errs...)
}
