# Tasks 002: stdio proxy, strict JSON-RPC, revision handling, audit log, terminal-safe output

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**JSON-RPC core**
- [x] **T1:** Add `github.com/go-json-experiment/json` to `go.mod`. Write a test that pins the verified defaults (duplicate names, invalid UTF-8, lone surrogates rejected; number literals exact), so a library upgrade that changes them fails CI. Open a GitHub issue to track moving to standard-library `encoding/json/v2`. (AC-7b, AC-9)
- [x] **T2:** `internal/jsonrpc` `ReadLine` with a byte cap and discard-to-newline: tests first (exactly max; max + 1 followed by a valid line, which must still be read; no newline at EOF; CRLF). (AC-10)
- [x] **T3:** `Parse` into the ordered `Value` tree, with Bulwark-counted depth and classification. Table tests first: request, response, notification, batch rejected, invalid JSON, duplicate key, `\xff`, `\ud800`, depth 65. (AC-7a, AC-7b, AC-10)
- [x] **T4:** `RouteScan`: tests first (single `id`; duplicated `id` → `null`; missing `id`; non-scalar `id`; truncated line; kind detection), then the lenient scanner. (AC-7)
- [x] **T5:** `Serialize`, with the property test (round-trip identity including big integers, `1.50e+10`, `-0`, unknown fields) and `FuzzParseSerialize`. (AC-2, AC-8, AC-9)
- [x] **T6:** `internal/canon`: canonical form with exact number literals. Tests first: RFC 8785 key order by UTF-16 code units, string escaping, number literals kept. (AC-21)

**Revisions**
- [x] **T7:** `internal/mcprev`: detection rules from DESIGN.md §5.2 as table tests, then the implementation, including `revision.unknown`, and `revision.mixed` that ignores a failed `server/discover` probe followed by `initialize`. (AC-15, AC-16, AC-17)
- [x] **T8:** Internal event mapping for both revisions; violation detection for server requests and misplaced `input_required` under 2026-07-28. (AC-18, AC-19)

**Pipeline and proxy**
- [x] **T9:** `internal/pipeline`: interceptor chain, verdicts, panic and error recovery → block (fault-injecting test first). (AC-26)
- [x] **T10:** Built-in interceptors: limits (size, depth, outstanding), revision, and the notification rate limit with aggregated records and the `list_changed` exception (always processed; forwarded coalesced). (AC-10, AC-14, AC-16, AC-33)
- [x] **T11:** Error-response helper for every code in DESIGN.md §6.6 (`-32700`, `-32600`, `-32603`, `-32010`, `-32022`, `-32601`), with tests asserting exact JSON, including `id: null`. (AC-7, AC-7a–c, AC-10, AC-16, AC-18, AC-19)
- [x] **T12:** Test helper binary `fakeupstream` (scripted behaviors: echo, stderr, exit code, ignore SIGTERM, fork a grandchild, unknown-ID response, malformed response, server request, notification flood). (test support)
- [x] **T13:** Child process in its own process group: `exec`, environment unchanged, stderr passthrough. Shutdown sequence (up to 5 s; SIGTERM to the group; up to 5 s; SIGKILL to the group; exit early when the child exits). Exit-code propagation; 70 on internal failure. Tests first, including the grandchild case. (AC-1, AC-3, AC-4, AC-5)
- [x] **T14:** SIGINT/SIGTERM handling: forward to the group, `stop` record, flush, exit. Test first. (AC-5a)
- [x] **T15:** Outstanding-request tables (both directions under 2025-11-25), unknown-ID drop, gateway-originated IDs (`bulwark-<hex>-<n>`, responses consumed). Tests first. (AC-11, AC-12, AC-13, AC-14)
- [x] **T16:** Wire the pipeline into both directions, with the reject-routing rules (AC-7) and the blocked-message rules (AC-26a): tests in both directions asserting who receives what and whether outstanding entries are cleared. (AC-7, AC-8, AC-18, AC-19, AC-26a)

**Audit**
- [x] **T17:** `internal/audit` writer: record struct (§6.5), canonical hashing, genesis value, HMAC key creation (`0600`), single-write records, 1 s `fsync`. Tests first. (AC-20, AC-21, AC-25)
- [x] **T18:** `Verify`: tamper tests (modify, insert, delete, reorder; truncation reported as a limitation, not as a pass). (AC-22)
- [x] **T19:** Fail-closed behavior on audit write failure in `enforce`; warn-only in `learn`/`warn`. Tests first. (AC-24)
- [x] **T20:** `Tail` with filters and `--follow`; golden output; every untrusted field through `termsafe`. (AC-23)

**Terminal safety, configuration, state**
- [x] **T21:** `internal/termsafe`: property test over every code point in Cc, Cf, Zl, and Zp, plus golden strings (the L-06 Tag payload, CSI, OSC 8, RLO), then the filter. (AC-27)
- [x] **T22:** `internal/config`: strict version-1 YAML, defaults, typed validation with `schemas/config.v1.json` published for editors (decision 44), invalid-config behavior per mode (in `cmd/bulwark`). Tests first. (AC-28)
- [x] **T23:** `internal/state`: `state_dir` creation and modes, permission warnings and the refusal in `enforce`, `command_digest`, default `server_id`. Tests first. (AC-29, AC-30)

**CLI**
- [x] **T24:** `cmd/bulwark`: `wrap`, `audit verify`, `audit tail`, `version`; the exit codes from DESIGN.md §6.1; golden `--help` output. (AC-1, AC-5, AC-22, AC-23)

**Suite, performance, CI**
- [x] **T25:** `lab/suite/transparency_test.go`: every scenario and revision, `none` vs. `learn` through `bulwark wrap`, comparing observation logs and parsed received messages. (AC-6)
- [x] **T26:** A generated message mix in `internal/pipeline/testdata/transcript.jsonl`; the benchmark; the p95 gate as `TestLatencyGate`, including the audit write (decision 44). (AC-31)
- [x] **T27:** Extend the `tools/meta` import check to `cmd/` and `internal/`; confirm that the `bulwark` process appears in the spec 001 trace and creates no `AF_INET`/`AF_INET6` sockets. (AC-32)
- [x] **T28:** `tools/meta hidden`: fixtures first (RLO, ZWSP, Tag character, a plain file), then the check over all tracked text files; add it to the `meta` job. (AC-34)
- [x] **T29:** Fuzz job in `ci.yml` (60 s per target on PRs; nightly 10 min in `nightly.yml`). (AC-9)

**Close-out**
- [x] **T30:** README: install-from-source instructions for `bulwark wrap`, and a "Limitations" section that leads with the AR-1 container guidance and says that Bulwark adds no request timeout (AC-7). Update DESIGN.md if anything changed.
- [x] **T31:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`.
