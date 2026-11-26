# Tasks 002: stdio proxy, strict JSON-RPC, revision handling, audit log, terminal-safe output

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**JSON-RPC core**
- [ ] **T1:** Add `github.com/go-json-experiment/json` to `go.mod`. Write a test that pins the verified defaults (duplicate names, invalid UTF-8, lone surrogates rejected; number literals exact), so a library upgrade that changes them fails CI. (AC-7, AC-9)
- [ ] **T2:** `internal/jsonrpc` `ReadLine`, with a byte cap: tests first (exactly max; max + 1; no newline at EOF; CRLF). (AC-10)
- [ ] **T3:** `Parse` into the ordered `Value` tree, plus classification. Table tests first: request, response, notification, batch rejected, duplicate key, `\xff`, `\ud800`, depth 65. (AC-7, AC-10)
- [ ] **T4:** `Serialize`, with the property test (round-trip identity including big integers, `1.50e+10`, unknown fields) and `FuzzParseSerialize`. (AC-2, AC-8, AC-9)
- [ ] **T5:** `internal/canon`: canonical form with exact number literals. Tests first: key order by UTF-16 code units (RFC 8785), string escaping, number literals kept. (AC-21)

**Revisions**
- [ ] **T6:** `internal/mcprev`: detection rules from DESIGN.md §5.2 as table tests, then the implementation, including `revision.unknown` and `revision.mixed`. (AC-15, AC-16, AC-17)
- [ ] **T7:** Internal event mapping for both revisions (metadata, `ToolViewStale`, `InputRequired`, `ServerRequest`); violation detection for server requests and misplaced `input_required` under 2026-07-28. (AC-18, AC-19)

**Pipeline and proxy**
- [ ] **T8:** `internal/pipeline`: interceptor chain, verdicts, panic and error recovery → block `-32603` (fault-injecting test first). (AC-26)
- [ ] **T9:** Built-in interceptors: limits (size, depth, outstanding), revision, notification rate limit with aggregated records. (AC-10, AC-14, AC-16, AC-33)
- [ ] **T10:** Error-response helper for every code in DESIGN.md §6.6, with tests asserting exact JSON. (AC-7, AC-10, AC-16, AC-18, AC-19)
- [ ] **T11:** `internal/proxy`: a test helper binary `fakeupstream` (scripted behaviors: echo, stderr, exit code, ignore SIGTERM, unknown-ID response, server request, flood). (test support)
- [ ] **T12:** Child process start (`exec`, environment unchanged, stderr passthrough) and the shutdown sequence (5 s, SIGTERM, 5 s, SIGKILL; exit-code propagation; 70 on internal failure). Tests first. (AC-1, AC-3, AC-4, AC-5)
- [ ] **T13:** Outstanding-request tables (both directions under 2025-11-25), unknown-ID drop, gateway-originated IDs (`bulwark-<hex>-<n>`, responses consumed). Tests first. (AC-11, AC-12, AC-13, AC-14)
- [ ] **T14:** Wire the pipeline into both directions; violation handling as AC-7 describes for requests, responses, and notifications. (AC-7, AC-8, AC-18, AC-19)

**Audit**
- [ ] **T15:** `internal/audit` writer: record struct (§6.5), canonical hashing, genesis value, HMAC key creation (`0600`), single-write records, 1 s `fsync`. Tests first. (AC-20, AC-21, AC-25)
- [ ] **T16:** `Verify`: tamper tests (modify, insert, delete, reorder; truncation reported as a limitation, not a pass claim). (AC-22)
- [ ] **T17:** Fail-closed behavior on audit write failure in `enforce`; warn-only in `learn`/`warn`. Tests first. (AC-24)
- [ ] **T18:** `Tail` with filters and `--follow`; golden output; every untrusted field through `termsafe`. (AC-23)

**Terminal safety, configuration, state**
- [ ] **T19:** `internal/termsafe`: property test and golden strings first (CSI, OSC 8, RLO, ZWJ, BOM), then the filter. (AC-27)
- [ ] **T20:** `internal/config`: strict version-1 YAML, defaults, embedded schema `schemas/config.v1.json`, invalid-config behavior per mode. Tests first. (AC-28)
- [ ] **T21:** `internal/state`: `state_dir` creation and modes, permission warnings and the refusal in `enforce`, `command_digest`, default `server_id`. Tests first. (AC-29, AC-30)

**CLI**
- [ ] **T22:** `cmd/bulwark`: `wrap`, `audit verify`, `audit tail`, `version`; the exit codes from DESIGN.md §6.1; golden `--help` output. (AC-1, AC-5, AC-22, AC-23)

**Suite, performance, CI**
- [ ] **T23:** `lab/suite/transparency_test.go`: every scenario and revision, `none` vs. `learn` through `bulwark wrap`, comparing observation logs and parsed received messages. (AC-6)
- [ ] **T24:** Record transcripts into `internal/pipeline/testdata/transcripts/`; write the benchmark and `tools/benchgate` (p95 from samples); add the gate to `ci.yml`. (AC-31)
- [ ] **T25:** Extend `tools/meta` imports to `cmd/` and `internal/`; confirm the `bulwark` process appears in the spec 001 trace and makes no `AF_INET`/`AF_INET6` sockets. (AC-32)
- [ ] **T26:** Fuzz job in `ci.yml` (60 s per target on PRs; nightly 10 min in `nightly.yml`). (AC-9)

**Close-out**
- [ ] **T27:** README: install-from-source instructions for `bulwark wrap`, and the "Limitations" section with AR-1 container guidance first. Update DESIGN.md if anything changed.
- [ ] **T28:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`.
