# Tasks 003: Fingerprints, pin store, modes, verify-before-call, server metadata

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**Fingerprints and identity**
- [ ] **T1:** `fingerprint.go`: golden-fingerprint tests and the one-leaf-mutation property test first (every field, including `icons`, `_meta`, and unknown fields, changes the result), then tool fingerprints. (AC-1)
- [ ] **T2:** Whole-result metadata fingerprints for both revisions, ignoring the volatile members `ttlMs`, `cacheScope`, and `resultType`; tests that absent ≠ `null` and that unknown `_meta` keys count. (AC-2)
- [ ] **T3:** `exclude_fields` handling, plus the `pin_event` on change. (AC-1, AC-3)
- [ ] **T4:** Duplicate-name detection within a page and across pages; `pin.duplicate_name`. (AC-1a)
- [ ] **T5:** `command_digest` mismatch → everything `changed`; the unpinned-package detection table from plan.md (ranges and dist-tags count as unpinned). (AC-4, AC-5)

**Pin store**
- [ ] **T6:** `store.go` load, save, and format (`schema_version: 1`, §6.4), with round-trip tests. (AC-6)
- [ ] **T7:** Atomic save (temp + rename), mode `0600`, advisory lock; test with 8 concurrent writers; crash-simulation test; store identity `(dev, inode, size, mtime)` with reload under the lock. (AC-6, AC-16a)
- [ ] **T8:** Status transitions: only `learn` and the store API may approve; `learn` never changes `rejected`. A fuzz test drives random MCP sequences in `warn`/`enforce` and asserts no status changes. (AC-7, AC-9)
- [ ] **T9:** `arg_roles` stored from configuration; `pin_event` on change. (AC-8)

**Modes**
- [ ] **T10:** `Decide` with the exhaustive, totality-checking table test from plan.md, including duplicate names and `findings_at_approval` matching. (AC-9–AC-14)
- [ ] **T11:** `ToolsListInterceptor`: per-page filtering in `enforce` (including duplicates), `nextCursor` kept; findings and controls in `warn`; pinning in `learn`. Integration tests through `bulwark wrap`. (AC-10, AC-11)
- [ ] **T12:** `ToolCallPinInterceptor`: `-32602 Unknown tool: <name>` for hidden, unapproved, changed, rejected, duplicated, or unknown tools in `enforce`. (AC-12)
- [ ] **T13:** `MetadataInterceptor`: the reduced result in `enforce` (keep list from AC-13; `name`/`version` capped at 128 characters with `pin.metadata_truncated`); both revisions. (AC-13)
- [ ] **T14:** Analyzer hook with a stub analyzer: a high finding hides or strips unless it is listed in `findings_at_approval`; a `learn` approval records no findings. (AC-14)
- [ ] **T15:** `list_changed` to the client when a store change makes a hidden tool visible; tagged with the listen stream's `subscriptionId` under 2026-07-28, and only if a stream is open. (AC-14a)

**Gateway-originated requests and re-check**
- [ ] **T16:** Bulwark's own `server/discover` before the first modern non-discover request; `_meta` copied from the triggering request; consumed, never forwarded; once per process. (AC-15, AC-15a)
- [ ] **T17:** Timeout (`limits.gateway_request_timeout`, 10 s) and failure handling: discover failure → reduced metadata; re-check failure → call blocked (`pin.recheck_failed`). (AC-15b)
- [ ] **T18:** Paginated re-check `tools/list`, with the 100-page and 16 MiB caps and fail-closed behavior. (AC-15c)
- [ ] **T19:** `ttlMs` normalization table test (`-1`, `0`, `1`, `1.5`, `1e300`, absent, mixed across pages), then `normalize`. (AC-16)
- [ ] **T20:** `view.go` staleness with an injected clock: `ageThreshold = max(min(ttl, maxAge), minAge)`; event triggers (notification, store change) on the 1 s tier; age re-checks at `min_age`; the `ttlMs: 1000` 60-second test with zero blocks; stale while rate-limited → `pin.recheck_pending`; configuration validation `min_age <= max_age`. (AC-16a, AC-16b, AC-17, AC-17a)
- [ ] **T21:** Verify-before-call integration: a fake upstream changes a tool **without** notifying; the call is blocked on fingerprint mismatch. (AC-17)
- [ ] **T22:** Record raw `ttlMs`, `cacheScope`, and the normalized hint in audit records. (AC-18)

**Suite, docs, performance**
- [ ] **T23:** Update `L-02.yaml` (setup `{approve: all, approve_metadata: true}`) and `L-07.yaml` (setup `{approve: all, approve_metadata: false}`) per AC-19, removing `pending: spec-003`; the suite must pass on Linux and macOS. (AC-19)
- [ ] **T24:** README results table for L-02 and L-07, plus the L-07 note on `canary_exfiltrated`. (AC-20)
- [ ] **T25:** Benchmark with pinning enabled; the gate still passes. (AC-21)
- [ ] **T26:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`. The spec 001 AC-29 check then confirms no `pending: spec-003` remains.
