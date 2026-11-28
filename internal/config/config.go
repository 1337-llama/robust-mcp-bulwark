// Package config loads the version-1 YAML configuration (DESIGN.md §6.3;
// spec 002 AC-28). Unknown keys are errors; omitted keys get the defaults.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Version   int               `yaml:"version"`
	Servers   map[string]Server `yaml:"servers"`
	Policy    Policy            `yaml:"policy"`
	Analyzers Analyzers         `yaml:"analyzers"`
	Secrets   Secrets           `yaml:"secrets"`
	MRTR      MRTR              `yaml:"mrtr"`
	Limits    Limits            `yaml:"limits"`
}

type Server struct {
	Mode             string                       `yaml:"mode"`
	PinRecheckMaxAge Duration                     `yaml:"pin_recheck_max_age"`
	PinRecheckMinAge Duration                     `yaml:"pin_recheck_min_age"`
	ArgRoles         map[string]map[string]string `yaml:"arg_roles"`
}

type Policy struct {
	BaselineAllow *bool    `yaml:"baseline_allow"`
	Dirs          []string `yaml:"dirs"`
	EvalTimeout   Duration `yaml:"eval_timeout"`
}

type Analyzers struct {
	Enabled *[]string `yaml:"enabled"` // nil: all four; []: none
}

type Secrets struct {
	Requests string `yaml:"requests"`
	Results  string `yaml:"results"`
}

type MRTR struct {
	Mode string `yaml:"mode"`
}

type Limits struct {
	MaxMessageBytes        int      `yaml:"max_message_bytes"`
	MaxDepth               int      `yaml:"max_depth"`
	MaxOutstandingRequests int      `yaml:"max_outstanding_requests"`
	NotificationsPerSecond int      `yaml:"notifications_per_second"`
	GatewayRequestTimeout  Duration `yaml:"gateway_request_timeout"`
}

// Duration accepts Go duration strings such as "30s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	d.Duration = v
	return nil
}

var (
	Modes         = []string{"learn", "warn", "enforce"}
	AllAnalyzers  = []string{"unicode.hidden", "text.imperative", "text.cross_reference", "schema.side_channel"}
	argRoles      = []string{"fs_path", "egress_url", "recipient"}
	secretActions = map[string][]string{"requests": {"deny", "redact", "audit"}, "results": {"redact", "audit"}}
)

// Default is the configuration used when no file exists.
func Default() *Config {
	c := &Config{Version: 1}
	c.applyDefaults()
	return c
}

// Load reads path; a missing file gives the defaults.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Config, error) {
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil && err != io.EOF {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Version != 1 {
		return nil, fmt.Errorf("config: version must be 1, got %d", c.Version)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	t := true
	if c.Policy.BaselineAllow == nil {
		c.Policy.BaselineAllow = &t
	}
	if c.Policy.EvalTimeout.Duration == 0 {
		c.Policy.EvalTimeout.Duration = 50 * time.Millisecond
	}
	if c.Analyzers.Enabled == nil {
		all := slices.Clone(AllAnalyzers)
		c.Analyzers.Enabled = &all
	}
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.Secrets.Requests, "deny")
	def(&c.Secrets.Results, "redact")
	def(&c.MRTR.Mode, "enforce")
	l := &c.Limits
	for _, p := range []struct {
		v *int
		d int
	}{{&l.MaxMessageBytes, 4 << 20}, {&l.MaxDepth, 64}, {&l.MaxOutstandingRequests, 256}, {&l.NotificationsPerSecond, 20}} {
		if *p.v == 0 {
			*p.v = p.d
		}
	}
	if l.GatewayRequestTimeout.Duration == 0 {
		l.GatewayRequestTimeout.Duration = 10 * time.Second
	}
	for id, s := range c.Servers {
		if s.PinRecheckMaxAge.Duration == 0 && s.PinRecheckMinAge.Duration == 0 {
			s.PinRecheckMaxAge.Duration, s.PinRecheckMinAge.Duration = 300*time.Second, 30*time.Second
		}
		c.Servers[id] = s
	}
}

func (c *Config) validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf("config: "+f, a...)) }
	for id, s := range c.Servers {
		if s.Mode != "" && !slices.Contains(Modes, s.Mode) {
			bad("servers.%s.mode %q is not learn, warn or enforce", id, s.Mode)
		}
		if s.PinRecheckMinAge.Duration > s.PinRecheckMaxAge.Duration {
			bad("servers.%s: pin_recheck_min_age must not exceed pin_recheck_max_age", id)
		}
		for tool, roles := range s.ArgRoles {
			for arg, role := range roles {
				if !slices.Contains(argRoles, role) {
					bad("servers.%s.arg_roles.%s.%s: unknown role %q", id, tool, arg, role)
				}
			}
		}
	}
	for _, a := range *c.Analyzers.Enabled {
		if !slices.Contains(AllAnalyzers, a) {
			bad("analyzers.enabled: unknown analyzer %q", a)
		}
	}
	if !slices.Contains(secretActions["requests"], c.Secrets.Requests) {
		bad("secrets.requests %q is not deny, redact or audit", c.Secrets.Requests)
	}
	if !slices.Contains(secretActions["results"], c.Secrets.Results) {
		bad("secrets.results %q is not redact or audit", c.Secrets.Results)
	}
	if c.MRTR.Mode != "enforce" && c.MRTR.Mode != "audit" {
		bad("mrtr.mode %q is not enforce or audit", c.MRTR.Mode)
	}
	for name, v := range map[string]int{"max_message_bytes": c.Limits.MaxMessageBytes, "max_depth": c.Limits.MaxDepth, "max_outstanding_requests": c.Limits.MaxOutstandingRequests, "notifications_per_second": c.Limits.NotificationsPerSecond} {
		if v < 0 {
			bad("limits.%s must not be negative (0 means the default)", name)
		}
	}
	durations := map[string]time.Duration{"policy.eval_timeout": c.Policy.EvalTimeout.Duration, "limits.gateway_request_timeout": c.Limits.GatewayRequestTimeout.Duration}
	for id, s := range c.Servers {
		durations["servers."+id+".pin_recheck_max_age"] = s.PinRecheckMaxAge.Duration
		durations["servers."+id+".pin_recheck_min_age"] = s.PinRecheckMinAge.Duration
	}
	for name, d := range durations {
		if d < 0 {
			bad("%s must not be negative", name)
		}
	}
	return errors.Join(errs...)
}
