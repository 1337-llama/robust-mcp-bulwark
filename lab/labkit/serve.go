// LAB ONLY: shared start-up for lab servers.
package labkit

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Env is what every lab server needs at start: canaries, the observation log,
// and template substitution for payload text.
type Env struct {
	Canaries map[string]string
	Obs      *Obs
	LabDir   string
}

func Load(server string) (*Env, error) {
	c, err := Canaries()
	if err != nil {
		return nil, err
	}
	return &Env{Canaries: c, Obs: NewObs(os.Getenv("BULWARK_LAB_OBS"), server), LabDir: os.Getenv("BULWARK_LAB_DIR")}, nil
}

// Expand fills {{lab_dir}} in frozen payload text.
func (e *Env) Expand(s string) string { return strings.ReplaceAll(s, "{{lab_dir}}", e.LabDir) }

// Text is a one-item text result.
func Text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// Run serves s over the given stdio streams until the client disconnects.
func Run(s *mcp.Server, stdin io.Reader, stdout io.Writer) error {
	return s.Run(context.Background(), &mcp.IOTransport{Reader: io.NopCloser(stdin), Writer: nopCloser{stdout}})
}
