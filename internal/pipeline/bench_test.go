package pipeline

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/1337-llama/robust-mcp-bulwark/internal/audit"
	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
	"github.com/1337-llama/robust-mcp-bulwark/internal/mcprev"
)

// corpus reads testdata/transcript.jsonl: a generated, representative message
// mix (discover, a 40-tool listing, tools/call requests and results, MRTR,
// notifications), not a recording of the lab suite (decision 44).
func corpus(t testing.TB) [][]byte {
	f, err := os.Open("testdata/transcript.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	return lines
}

// process is the per-message gateway work (AC-31): strict parse, the chain,
// re-serialize, and one audit record written to a temporary file.
func process(chain Chain, w *audit.Writer, line []byte, s *Session) {
	m, err := jsonrpc.Parse(line, 64)
	if err != nil {
		return
	}
	d := ClientToServer
	if m.Kind == jsonrpc.Response || (m.Kind == jsonrpc.Notification && m.Method != "notifications/initialized") {
		d = ServerToClient
	}
	res := chain.Run(context.Background(), m, d, s)
	if res.Msg != nil {
		jsonrpc.Serialize(res.Msg.Root)
	}
	w.Write(audit.Record{Event: "call_decision", Method: m.Method, Controls: res.Controls})
}

func writer(t testing.TB) *audit.Writer {
	dir := t.TempDir()
	w, err := audit.Open(filepath.Join(dir, "audit"), filepath.Join(dir, "audit.key"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func newChain() Chain {
	return Chain{Revision{Conn: &mcprev.Conn{}}, &RateLimit{PerSecond: 1 << 30, Now: time.Now}}
}

func BenchmarkPipeline(b *testing.B) {
	lines, chain, s, w := corpus(b), newChain(), &Session{Mode: "enforce"}, writer(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		process(chain, w, lines[i%len(lines)], s)
	}
}

// Verifies: NFR-004 (spec 002 AC-31: p95 per message < 5 ms, in process, upstream excluded)
func TestLatencyGate(t *testing.T) {
	lines, chain, s, w := corpus(t), newChain(), &Session{Mode: "enforce"}, writer(t)
	var samples []time.Duration
	for round := 0; round < 50; round++ {
		for _, l := range lines {
			t0 := time.Now()
			process(chain, w, l, s)
			samples = append(samples, time.Since(t0))
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p95 := samples[len(samples)*95/100]
	t.Logf("p95 %v over %d messages", p95, len(samples))
	if p95 >= 5*time.Millisecond {
		t.Fatalf("p95 %v >= 5 ms (NFR-004)", p95)
	}
}
