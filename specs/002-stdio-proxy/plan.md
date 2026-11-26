# Plan 002: stdio proxy, strict JSON-RPC, revision handling, audit log, terminal-safe output

## Approach
This implements DESIGN.md §5.1 (pipeline), §5.2 (revisions), §5.8 (audit), §6.1 (CLI), §6.3 (configuration), §6.5 (audit record), §6.6 (error responses), and §9 (state and operations), in the packages listed in §4.2.

**JSON library (decided, verified):** `github.com/go-json-experiment/json/jsontext` (BSD-3-Clause, by the Go authors). It is the same code as the standard library's `encoding/json/v2`, which still needs the `goexperiment.jsonv2` build tag on Go's `master` as of 2026-11-26. A test program run on 2026-11-26 against v1.27.2 confirmed that, **with default options**, `jsontext`:
- rejects duplicate object member names
- rejects invalid UTF-8
- rejects lone surrogate escapes (`\ud800`)
- returns number tokens with their exact literal (`12345678901234567890123`, `1.50e+10`)
- enforces a maximum nesting depth

Bulwark sets its own lower depth limit (64). When the standard library's `encoding/json/v2` becomes non-experimental, switching is a one-package import change. This is tracked in a GitHub issue opened with T1 (Dependabot doesn't read TODOs). `jsontext`'s own depth cap (10000) isn't configurable, so `Parse` counts depth itself against `limits.max_depth` (64).

## Modules and files
| Path | New/Changed | Responsibility |
|---|---|---|
| `cmd/bulwark/main.go` | New | `wrap`, `audit verify`, `audit tail`, `version`; exit codes from §6.1 |
| `internal/jsonrpc/` | New | Line reader with a byte cap (discards to the next newline when over); strict parse into `Message` (an ordered tree with raw number literals); `Serialize`; classification; **`RouteScan`**, the best-effort scan used only to address errors for rejected lines (AC-7) |
| `internal/canon/` | New | Canonical form (JCS key order and string rules, exact number literals; DESIGN.md §5.3). Used by the audit chain now and by fingerprints in spec 003 |
| `internal/mcprev/` | New | Revision detection (§5.2) and the internal event model (`ServerMetadata`, `ToolViewStale`, `InputRequired`, `ServerRequest`) |
| `internal/proxy/` | New | Child process in its own process group (`SysProcAttr.Setpgid`), with signals sent to the group; SIGINT/SIGTERM forwarding; pipes; stderr passthrough; the shutdown sequence; two reader goroutines; per-pipe writer mutex; outstanding-request tables; gateway-originated requests; the reject-routing table (AC-7, AC-26a) |
| `internal/pipeline/` | New | Interceptor interface (§5.1), ordered chain, panic recovery, built-in interceptors: limits, revision, ID tracking, notification rate limit |
| `internal/audit/` | New | Writer (hash chain, HMAC key, single-write records, periodic `fsync`, fail-closed signal), `Verify`, `Tail` |
| `internal/config/` | New | Strict YAML loading (version 1), defaults, validation, embedded JSON Schema published at `schemas/config.v1.json` |
| `internal/state/` | New | `state_dir` creation and permission checks; `command_digest`; default `server_id` |
| `internal/termsafe/` | New | Escapes every code point in Unicode categories Cc, Cf, Zl, and Zp as `\u{XXXX}` (Go `unicode.Cc`, `unicode.Cf`, `unicode.Zl`, `unicode.Zp` tables) |
| `lab/suite/transparency_test.go` | New | AC-6: compares `none` with `learn` through `bulwark wrap` for every scenario and revision |
| `.github/workflows/ci.yml` | Changed | Benchmark gate (AC-31); fuzz job (60 s per target on PRs) |
| `tools/meta` | Changed | Import check extended to `cmd/` and `internal/` (AC-32); hidden-character check over all tracked text files (AC-34) |
| `tools/benchgate/` | New | Reads benchmark samples and fails if p95 ≥ 5 ms (AC-31) |

## Interfaces and data structures
```go
// internal/jsonrpc
type Kind int // Request, Response, Notification

type Message struct {
	Kind   Kind
	ID     *Value  // raw id, kept exactly (string or number literal)
	Method string  // requests and notifications
	Root   *Value  // the whole message as an ordered tree
}

type Value struct { // ordered JSON tree
	Kind    ValueKind        // Object, Array, String, Number, Bool, Null
	Members []Member         // objects, in received order
	Elems   []*Value         // arrays
	Str     string           // decoded string (valid UTF-8)
	Num     string           // exact number literal
	Bool    bool
}
type Member struct{ Name string; Value *Value }

func ReadLine(r *bufio.Reader, max int) ([]byte, error)   // never buffers more than max+1 bytes
func Parse(line []byte, maxDepth int) (*Message, error)   // jsontext with default (strict) options; depth counted here

// RouteScan is lenient and used ONLY to address an error for a rejected line (AC-7).
// id is returned only if "id" appears exactly once at the top level with a string or number value.
func RouteScan(line []byte) (kind Kind, id *Value, ok bool)
func Serialize(m *Message) []byte                         // compact, same member order, minimal escaping
```

```go
// internal/pipeline
type Direction int // ClientToServer, ServerToClient
type Verdict int   // Forward, Modify, Block

type Interceptor interface {
	Name() string
	Match(m *jsonrpc.Message, d Direction, rev mcprev.Revision) bool
	Handle(ctx context.Context, m *jsonrpc.Message, s *Session) (Verdict, *jsonrpc.Message, []Finding, error)
}
```

**Audit record:** exactly the DESIGN.md §6.5 fields. `canon.Canonical(record)` provides the bytes that are hashed. The genesis value is `SHA-256("mcp-bulwark-audit-v1")`. The HMAC key lives at `<state_dir>/audit.key`: 32 random bytes, mode `0600`, created once.

**Error responses:** exactly DESIGN.md §6.6 (`-32600`, `-32603`, `-32010`, `-32022`, `-32601`), built by one helper so the codes live in one place.

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1, AC-3, AC-4, AC-5, AC-5a | Integration: a small fake upstream (test helper binary) that echoes, writes stderr, exits with given codes, ignores SIGTERM, or **forks a grandchild**. Assertions: the group is signaled, no process outlives the gateway, early exit when the child exits | `internal/proxy/proxy_test.go` |
| AC-2, AC-8, AC-9 | Property test (`testing/quick` generator of valid JSON-RPC messages) and Go fuzz target `FuzzParseSerialize` | `internal/jsonrpc/` |
| AC-6 | Suite transparency test | `lab/suite/transparency_test.go` |
| AC-7, AC-7a–c, AC-10 | Table tests with crafted lines: invalid JSON (`-32700`); duplicate `description`; duplicate `id` (→ `id: null`); `\xff`; `\ud800`; batch; 4 MiB + 1 (discard to newline, `id: null`); depth 65. Each in both directions, asserting **who** receives which error, and that the outstanding entry is cleared or kept as AC-7 says | `internal/jsonrpc/strict_test.go`, `internal/jsonrpc/routescan_test.go`, `internal/proxy/violations_test.go` |
| AC-11–AC-14 | Unit tests on the ID tables, plus integration with a fake upstream that answers unknown IDs or replays gateway IDs | `internal/proxy/ids_test.go` |
| AC-15–AC-19 | Unit tests on the §5.2 rules; integration with fake upstreams that send server requests or `input_required` on `tools/list` | `internal/mcprev/`, `internal/proxy/revision_test.go` |
| AC-20–AC-23, AC-25 | Unit tests on the chain; tamper tests (modify, insert, delete, reorder, truncate); golden output for `tail` | `internal/audit/` |
| AC-24 | Integration: `state_dir` on a full or read-only directory (`chmod 0500` on the audit directory), in `enforce` and `warn` | `internal/proxy/auditfail_test.go` |
| AC-26, AC-26a | A fault-injecting test interceptor, applied to a client request, a server response, a 2025-11-25 server request, and a notification, asserting the recipient of each error | `internal/pipeline/pipeline_test.go`, `internal/proxy/blocked_test.go` |
| AC-27 | Property test over all code points in Cc, Cf, Zl, Zp (from Go's `unicode` tables) and random runes; golden strings: the L-06 Tag-block payload, CSI color, OSC 8 hyperlink, RLO-reversed text | `internal/termsafe/` |
| AC-28–AC-30 | Unit tests: unknown keys, defaults, permission modes, digest of known argv | `internal/config/`, `internal/state/` |
| AC-31 | Benchmark over `testdata/transcripts/*.jsonl`, recorded from the spec 001 suite; CI computes p95 from `-benchtime` samples via a small helper | `internal/pipeline/bench_test.go`, `tools/benchgate/` |
| AC-32 | `tools/meta` import check; the spec 001 trace now includes `bulwark` | `tools/meta/` |
| AC-33 | Integration: a fake upstream sending 1,000 `notifications/progress` messages with `notifications/tools/list_changed` mixed in. Assert ≤ 20 forwarded per second, one `rate_limited` record per second, every `list_changed` processed internally, and at most one forwarded per second | `internal/pipeline/ratelimit_test.go` |
| AC-34 | Unit (fixture files with RLO, ZWSP, and a Tag character fail; plain files pass) | `tools/meta/hidden_test.go` |
| AC-17 (probe) | Unit: `server/discover` → error → `initialize` gives no finding; successful modern exchange → `initialize` gives a finding | `internal/mcprev/mixed_test.go` |

Every test carries `// Verifies:` tags for its FR/NFR IDs (spec 001 AC-26).

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| `go-json-experiment` changes its API before it becomes the standard library | Pinned in `go.mod`; all use goes through `internal/jsonrpc`, so only one package changes |
| Benchmark noise on shared runners | Gate set well above the expected cost (decision 22); p95 computed over many iterations |
| Signal handling differs on macOS | The shutdown test runs on both operating systems (macOS workflow from spec 001) |
| Re-serialization changes string escaping (for example `é` becomes `é`) | Allowed: the guarantee is semantic equality after parsing (AC-2), which is what clients read. Byte-identical forwarding is exactly what FR-028 forbids |
