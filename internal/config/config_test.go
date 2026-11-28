package config

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Verifies: FR-020 (AC-28: strict version-1 config, defaults, validation)
func TestParse(t *testing.T) {
	c, err := Parse([]byte(`version: 1
servers:
  fs:
    mode: enforce
    arg_roles:
      read_file: {path: fs_path}
secrets: {requests: audit}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Servers["fs"].PinRecheckMaxAge.Duration != 300*time.Second || c.Limits.MaxMessageBytes != 4<<20 || !*c.Policy.BaselineAllow ||
		c.Secrets.Requests != "audit" || c.Secrets.Results != "redact" || len(*c.Analyzers.Enabled) != 4 || c.Policy.EvalTimeout.Duration != 50*time.Millisecond {
		t.Errorf("defaults: %+v", c)
	}
	if c, err := Parse([]byte("version: 1\nanalyzers: {enabled: []}\n")); err != nil || len(*c.Analyzers.Enabled) != 0 {
		t.Errorf("explicit empty analyzer list must stay empty: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown key":   "version: 1\nlimts: {}\n",
		"version":       "version: 2\n",
		"mode":          "version: 1\nservers: {fs: {mode: block}}\n",
		"role":          "version: 1\nservers: {fs: {arg_roles: {t: {a: url}}}}\n",
		"min > max":     "version: 1\nservers: {fs: {pin_recheck_max_age: 10s, pin_recheck_min_age: 20s}}\n",
		"analyzer":      "version: 1\nanalyzers: {enabled: [magic]}\n",
		"secret action": "version: 1\nsecrets: {results: deny}\n",
		"duration":      "version: 1\npolicy: {eval_timeout: soon}\n",
		"negative":      "version: 1\npolicy: {eval_timeout: -1s}\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The published schema (for editors) must name exactly the keys the loader accepts.
func TestSchemaMatchesLoader(t *testing.T) {
	b, err := os.ReadFile("../../schemas/config.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties map[string]struct{ Properties map[string]any }
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	check := func(where string, typ reflect.Type, props map[string]any) {
		for i := 0; i < typ.NumField(); i++ {
			if _, ok := props[strings.Split(typ.Field(i).Tag.Get("yaml"), ",")[0]]; !ok {
				t.Errorf("%s: %s missing from the schema", where, typ.Field(i).Tag.Get("yaml"))
			}
		}
		if len(props) != typ.NumField() {
			t.Errorf("%s: schema has %d keys, loader %d", where, len(props), typ.NumField())
		}
	}
	top := map[string]any{}
	for k := range s.Properties {
		top[k] = nil
	}
	check("top level", reflect.TypeOf(Config{}), top)
	for key, typ := range map[string]reflect.Type{"policy": reflect.TypeOf(Policy{}), "analyzers": reflect.TypeOf(Analyzers{}), "secrets": reflect.TypeOf(Secrets{}), "mrtr": reflect.TypeOf(MRTR{}), "limits": reflect.TypeOf(Limits{})} {
		check(key, typ, s.Properties[key].Properties)
	}
}
