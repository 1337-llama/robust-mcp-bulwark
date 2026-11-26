# Tasks 003: Fingerprints, pin store, modes, verify-before-call, server metadata

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**Fingerprints and identity**
- [ ] **T1:** `fingerprint.go`: golden-fingerprint tests and the one-leaf-mutation property test first (every field, including `icons`, `_meta`, and unknown fields, changes the result), then tool fingerprints. (AC-1)
- [ ] **T2:** Metadata fingerprints for both revisions, with absent ≠ `null` tests. (AC-2)
- [ ] **T3:** `exclude_fields` handling, plus the `pin_event` on change. (AC-1, AC-3)
- [ ] **T4:** `command_digest` mismatch → everything `changed`; `identity.unpinned_package` detection table (`npx pkg`, `npx pkg@latest`, `npx pkg@1.2.3`, `uvx`, `docker run img:tag`, `docker run img@sha256:…`). (AC-4, AC-5)

**Pin store**
- [ ] **T5:** `store.go` load, save, and format (`schema_version: 1`, §6.4) with round-trip tests. (AC-6)
- [ ] **T6:** Atomic save (temp + rename), mode `0600`, advisory lock; test with 8 concurrent writers; crash-simulation test. (AC-6)
- [ ] **T7:** Status transitions: only `learn` and the store API may approve. A fuzz test drives random MCP sequences in `warn`/`enforce` and asserts no status changes. (AC-7)
- [ ] **T8:** `arg_roles` stored from configuration; `pin_event` on change. (AC-8)

**Modes**
- [ ] **T9:** `Decide` with an exhaustive table test from plan.md, including the high-finding row. (AC-9–AC-14)
- [ ] **T10:** `ToolsListInterceptor`: per-page filtering in `enforce`, `nextCursor` kept; findings and controls in `warn`; pinning in `learn`. Integration tests through `bulwark wrap`. (AC-9, AC-10, AC-11)
- [ ] **T11:** `ToolCallPinInterceptor`: `-32602 Unknown tool: <name>` for hidden, unapproved, changed, rejected, or unknown tools in `enforce`. (AC-12)
- [ ] **T12:** `MetadataInterceptor`: stripping `instructions` and every `serverInfo` member except `name`/`version` in `enforce`; both revisions. (AC-13)
- [ ] **T13:** Analyzer hook interface, with a stub analyzer that produces a high finding → hidden/stripped even when approved. (AC-14)

**Discover and re-check**
- [ ] **T14:** Bulwark's own `server/discover` before the first modern non-discover request; consumed, never forwarded; once per process. (AC-15)
- [ ] **T15:** `view.go` staleness with an injected clock: notification, `ttlMs`, `ttlMs: 0`, `ttlMs: 1`, max age, store `mtime`; the `min_age` rate limiter. (AC-16)
- [ ] **T16:** Verify-before-call: Bulwark's own paginated `tools/list` when stale in `enforce`; block on fingerprint mismatch. A fake upstream changes a tool **without** notifying. (AC-17)
- [ ] **T17:** Record `ttlMs` and `cacheScope` in audit records. (AC-18)

**Suite, docs, performance**
- [ ] **T18:** Update `L-02.yaml` and `L-07.yaml` per AC-19 (remove `pending: spec-003`); the suite must pass on Linux and macOS. (AC-19)
- [ ] **T19:** README results table for L-02 and L-07, plus the L-07 note on `canary_exfiltrated`. (AC-20)
- [ ] **T20:** Benchmark with pinning enabled; the gate still passes. (AC-21)
- [ ] **T21:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`. The spec 001 AC-29 check then confirms no `pending: spec-003` remains.
