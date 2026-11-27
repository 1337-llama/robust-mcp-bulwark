// LAB ONLY: test helper that runs one lab server over pipes and drives it with
// the replay client, returning the transcript and the observation log.
package labtest

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/1337-llama/robust-mcp-bulwark/lab/manifest"
	"github.com/1337-llama/robust-mcp-bulwark/lab/replay"
	"go.yaml.in/yaml/v3"
)

type Result struct {
	Transcript string
	Obs        string
	Err        error
}

// Run serves one lab server, runs a YAML script against it, and returns what happened.
func Run(t *testing.T, serve func(io.Reader, io.Writer) error, rev, script string, canaries map[string]string) Result {
	t.Helper()
	dir := t.TempDir()
	for _, err := range []error{
		os.MkdirAll(filepath.Join(dir, "private"), 0o700),
		os.MkdirAll(filepath.Join(dir, "workspace"), 0o700),
		os.WriteFile(filepath.Join(dir, "private", "secret.txt"), []byte(canaries["plain"]+"\n"), 0o600),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	obs := filepath.Join(dir, "obs.jsonl")
	cj, _ := json.Marshal(canaries)
	t.Setenv("BULWARK_LAB_CANARIES", string(cj))
	t.Setenv("BULWARK_LAB_DIR", dir)
	t.Setenv("BULWARK_LAB_OBS", obs)
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- serve(sr, sw); sw.Close() }()
	var steps []manifest.Step
	if err := yaml.Unmarshal([]byte(script), &steps); err != nil {
		t.Fatal(err)
	}
	var tr bytes.Buffer
	c := replay.New(cr, cw, rev, &tr)
	runErr := c.Run(steps, replay.Vars{Canaries: canaries, LabDir: dir})
	cw.Close()
	<-errc
	<-c.Done()
	ob, _ := os.ReadFile(obs)
	return Result{Transcript: tr.String(), Obs: string(ob), Err: runErr}
}
