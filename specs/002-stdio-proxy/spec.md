# Spec 002: stdio proxy, strict JSON-RPC, revision handling, audit log, terminal-safe output

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-020, FR-026, FR-028, FR-029, FR-031, FR-036, NFR-004, NFR-005, NFR-006, NFR-007, NFR-013, NFR-014; threats T-01, T-03, T-04, T-09, T-10, T-11, T-15, T-17 |
| Milestone | M1 |
| Depends on | Spec 001 (the suite is used for the transparency test) |

## Summary
This spec builds the gateway's foundation: `bulwark wrap -- <server command>`. Bulwark starts the real server and sits on both pipes. Every message is parsed strictly, re-serialized losslessly, tagged with its protocol revision, and recorded in a tamper-evident audit log. The audit log has its own `verify` and `tail` commands, and everything printed from it is terminal-safe.

There are **no security controls yet**: pinning, analyzers, policy, and secrets arrive in specs 003–007. What this spec proves is that Bulwark is **transparent**: every spec 001 attack still works through Bulwark in `learn` mode, with identical results. It also proves Bulwark is **hard to confuse**: duplicate keys, broken encodings, oversized input, response-ID tricks, and revision tricks are all rejected and recorded.

## User stories
- As a **developer**, I want to put Bulwark in front of any stdio MCP server without changing behavior, so I can adopt it with a one-line config change.
- As a **security reviewer**, I want proof that Bulwark and the client can never read the same message differently, so analyzers added later can't be bypassed by parser tricks.
- As an **IR analyst**, I want a log of everything that passed through, with proof that nobody altered it, and output that a malicious server can't use to mess up my terminal.

## Acceptance criteria (EARS)

**Proxy and process lifecycle (FR-020)**
- **AC-1:** WHEN started as `bulwark wrap [flags] -- <command> [args…]`, THE gateway SHALL:
  - start `<command>` directly with `exec` (no shell), with the client's environment unchanged
  - proxy newline-delimited JSON-RPC between its own stdin/stdout and the child's
- **AC-2:** WHILE no control applies (this spec has none), THE gateway SHALL forward every valid message so that parsing the output gives exactly the same value as parsing the input: same members in the same order, unknown fields kept, number literals unchanged.
- **AC-3:** THE gateway SHALL pass the child's stderr through byte-for-byte to its own stderr.
- **AC-4:** WHEN the client closes stdin, THE gateway SHALL:
  - close the child's stdin
  - wait 5 s, then send SIGTERM
  - wait another 5 s, then send SIGKILL
  - exit with the child's exit code
- **AC-5:** WHEN the child exits, THE gateway SHALL flush the audit log and exit with the child's exit code. IF Bulwark itself fails, THEN it SHALL write a `bulwark:`-prefixed line to stderr, write a `stop` record with `reason: internal_error`, and exit with code 70.
- **AC-6 (transparency, M1 exit):** For every spec 001 scenario and revision, a run through `bulwark wrap --mode learn` SHALL produce the same observation log and the same received messages as the `none` condition. Messages are compared after parsing.

**Strict parsing and lossless forwarding (FR-028, T-01)**
- **AC-7:** IF a message contains a duplicate object member name, invalid UTF-8, or a `\u` escape that encodes a lone UTF-16 surrogate, THEN THE gateway SHALL NOT forward it and SHALL record a `protocol_violation` audit record. Additionally:
  - IF the message is a request, THEN the sender SHALL receive JSON-RPC error `-32600`.
  - IF it is a response to a known request, THEN the original requester SHALL receive error `-32603` with message `upstream protocol violation`.
  - Otherwise it SHALL be dropped.
- **AC-8:** THE gateway SHALL forward only the re-serialized form of the message it parsed, never the original bytes.
- **AC-9:** A property test SHALL show that, for generated valid messages, parse → serialize → parse yields an identical value, including integers above 2^53, number literals such as `1.50e+10`, and unknown fields. A Go fuzz target SHALL show that the parser never panics and that anything it accepts round-trips.
- **AC-10** (NFR-013): IF a line exceeds `limits.max_message_bytes` (default 4 MiB) or nesting exceeds `limits.max_depth` (default 64), THEN THE gateway SHALL treat it as in AC-7, but with error code `-32010` and a `limit_exceeded` record. THE reader SHALL never buffer more than `max_message_bytes` + 1 bytes of a line.

**Request IDs (FR-031, T-04)**
- **AC-11:** THE gateway SHALL track outstanding client-to-server requests by `id`. IF the server sends a response whose `id` matches no outstanding request, THEN THE gateway SHALL drop it and record a `protocol_violation`.
- **AC-12:** UNDER revision `2025-11-25`, THE gateway SHALL also track server-to-client requests and match the client's responses to them, in the same way.
- **AC-13:** THE gateway SHALL provide a facility for gateway-originated requests:
  - IDs have the form `bulwark-<128-bit random hex>-<counter>`, with the prefix chosen once per process.
  - Responses to them are delivered to the gateway and never forwarded.

  It is unit-tested here and used by spec 003.
- **AC-14:** IF the number of outstanding requests would exceed `limits.max_outstanding_requests` (default 256), THEN the new request SHALL get error `-32010` and a `limit_exceeded` record.

**Protocol revisions (FR-036, T-17)**
- **AC-15:** THE gateway SHALL assign each message a revision using the rules in DESIGN.md §5.2, and record it in every audit record.
- **AC-16:** WHILE in `enforce` mode, IF a request's revision is unknown or unsupported, THEN THE gateway SHALL answer with error `-32022` (`UnsupportedProtocolVersionError`) listing `2026-07-28` and `2025-11-25`. In `learn` and `warn` modes it SHALL forward the request and record a `revision.unknown` finding.
- **AC-17:** WHEN a connection carries both a legacy `initialize` and requests with modern `_meta` versions, THE gateway SHALL record a `revision.mixed` finding.
- **AC-18:** UNDER revision `2026-07-28`, IF the server writes a JSON-RPC request to stdout, THEN THE gateway SHALL record a `protocol_violation`. In `enforce` mode it SHALL NOT forward it, and SHALL answer the server with `-32601`. In `learn` and `warn` modes it SHALL forward it.
- **AC-19:** UNDER revision `2026-07-28`, IF a result has `resultType: "input_required"` for any method other than `tools/call`, `prompts/get`, or `resources/read`, THEN THE gateway SHALL record a `protocol_violation`. In `enforce` mode the client SHALL receive error `-32603` instead.

**Audit log (FR-026, NFR-006, T-09, T-10)**
- **AC-20:** THE gateway SHALL write one audit record per message it forwards, blocks, or rejects, plus `start` and `stop` records. Records use the fields in DESIGN.md §6.5 and the file layout in §5.8.
- **AC-21:** THE records SHALL form a hash chain: `hash = SHA-256(prev_hash ‖ canonical(record without hash))`, where the first record links to a fixed genesis value. Argument values SHALL be stored only as `args_mac`: HMAC-SHA-256 under a per-install key, created with mode `0600` on first use.
- **AC-22:** WHEN `bulwark audit verify` runs, it SHALL exit 0 for an intact log. It SHALL exit 3 and name the first bad record for any modified, inserted, deleted, or reordered record. Its output SHALL state that tail truncation and whole-file rewrites are detectable only with an external anchor (AR-6).
- **AC-23:** `bulwark audit tail` SHALL support `--server-id`, `--event`, `--follow`, and `--json`. Every untrusted field it prints SHALL pass through the terminal-safety filter (AC-27).
- **AC-24:** WHILE in `enforce` mode, IF an audit record can't be written, THEN THE gateway SHALL stop forwarding:
  - `tools/call` gets a tool result with `isError: true` and the text `Blocked by MCP Bulwark (audit log unavailable)`
  - other requests get error `-32603`
  - stderr gets one `audit_error` line

  In `learn` and `warn` modes it SHALL keep forwarding and warn on stderr.
- **AC-25:** THE writer SHALL write each record as a single `write` call and `fsync` at least once per second and on exit.

**Fail-closed pipeline (NFR-005, T-15)**
- **AC-26:** IF an interceptor panics or returns an error, THEN THE gateway SHALL recover, treat the message as blocked with error `-32603`, and record the failure, without crashing. A test interceptor injects the fault.

**Terminal safety (FR-029, T-11)**
- **AC-27:** THE `termsafe` filter SHALL render visibly, as `\x1b`, `‮`, and so on, every C0 and C1 control character (including ESC, so no escape sequence survives), DEL, the bidi controls U+202A–U+202E and U+2066–U+2069, and zero-width characters (U+200B–U+200D, U+FEFF). A property test SHALL show that no output contains any of them raw.

**Configuration, state, and identity**
- **AC-28:** THE gateway SHALL load the version-1 YAML configuration (DESIGN.md §6.3), rejecting unknown keys. Defaults are as in §6.1 and §6.3. IF the configuration is invalid in `enforce` mode, THEN `wrap` SHALL exit 1 without starting the child.
- **AC-29:** THE gateway SHALL create `state_dir` with mode `0700` and its files with mode `0600`. It SHALL warn if any are group- or world-writable, and in `enforce` mode SHALL refuse to start (T-08).
- **AC-30:** `--server-id` SHALL be required in `enforce` mode. In `learn` and `warn` modes the default SHALL be `auto-<first 12 hex digits of command_digest>`, printed to stderr. `command_digest` is computed as in DESIGN.md §5.3.

**Performance and attack surface**
- **AC-31** (NFR-004): A Go benchmark over the recorded spec 001 transcripts SHALL measure the in-process pipeline (parse, intercept, serialize, audit to a temporary file). The CI gate SHALL fail if p95 is ≥ 5 ms per message.
- **AC-32** (NFR-007, NFR-014): THE gateway's own packages SHALL NOT import `net`, `net/http`, or `net/rpc` (the spec 001 import check is extended to `cmd/` and `internal/`). Spec 001's syscall-traced suite SHALL also cover the `bulwark` process, now that the `learn` transparency runs use it.
- **AC-33** (NFR-013): IF server notifications exceed `limits.notifications_per_second` (default 20), THEN THE excess SHALL be dropped, with one aggregated `rate_limited` record per second, not one per message.

## Out of scope
Pinning, server-metadata pinning, and Bulwark's own `server/discover` (spec 003); analyzers (004); the `tools` CLI (005); policy and MRTR checks (006); secret detection (007); demo and release (008). The spec 001 `warn`/`enforce` expectations stay `pending`.

## Open questions
None. Library choice, data structures, and test layout are in [plan.md](plan.md).
