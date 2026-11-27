# Plan 003: Fingerprints, pin store, modes, verify-before-call, server metadata

## Approach
This implements DESIGN.md §5.3 (identity, fingerprints, pin store, modes, re-check schedule), the metadata parts of §5.2, and the §6.4 file format. It reuses spec 002's `internal/canon`, its gateway-originated requests, the pipeline, and the audit log. Three new interceptors plug into the §5.1 order: metadata, `tools/list`, and the `tools/call` pin check.

## Modules and files
| Path | New/Changed | Responsibility |
|---|---|---|
| `internal/registry/fingerprint.go` | New | Tool and metadata fingerprints (AC-1, AC-2), `exclude_fields` handling |
| `internal/registry/store.go` | New | Pin store: load, atomic save, advisory lock (`syscall.Flock` on Linux and macOS; Windows best-effort with an exclusive-create lock file), status transitions, `mtime` tracking |
| `internal/registry/view.go` | New | The current tool view: fingerprints by name, `fetched_at`, `ttlMs`, stale flag, and the re-check rate limiter |
| `internal/registry/modes.go` | New | Decision table for `learn`, `warn`, `enforce` × new, unchanged, changed, rejected × high finding |
| `internal/pipeline/pin_interceptors.go` | New | `MetadataInterceptor` (server→client discover or initialize result), `ToolsListInterceptor` (server→client `tools/list` result), `ToolCallPinInterceptor` (client→server `tools/call`) |
| `internal/proxy/discover.go` | New | Bulwark's own `server/discover` before the first modern client request (AC-15), and its own paginated `tools/list` for re-checks (AC-17) |
| `internal/state/identity.go` | Changed | `identity.unpinned_package` detection (AC-5) |
| `lab/scenarios/L-02.yaml`, `L-07.yaml` | Changed | Remove `pending: spec-003`; set the expectations from AC-19 |
| `README.md` | Changed | Results table rows for L-02 and L-07; L-07 note (AC-20) |

## Interfaces and data structures
```go
// internal/registry
type Status string // "pending" | "approved" | "rejected"

type ToolPin struct {
	Fingerprint        string          `json:"fingerprint"`
	Snapshot           json.RawMessage `json:"snapshot"`          // as received, for diffs (spec 005)
	ExcludeFields      []string        `json:"exclude_fields"`
	ArgRoles           map[string]string `json:"arg_roles"`
	Status             Status          `json:"status"`
	ApprovedAt         string          `json:"approved_at,omitempty"`
	FindingsAtApproval []Finding       `json:"findings_at_approval"`
}

type Verdict int // Visible, Hidden

// Decide is pure: easy to table-test against the modes table in DESIGN.md §5.3.
func Decide(mode Mode, pin *ToolPin, currentFP string, highFinding bool) (Verdict, []Finding, []string /*controls*/)
```

**Decision table** (`modes.go`). It is **total**: the exhaustive test enumerates every mode × pin state × high-finding combination and fails on any missing cell.

| Pin state | `learn` | `warn` | `enforce` |
|---|---|---|---|
| missing | pin `approved`, visible, `pin_event` | visible; `pin.unapproved` / `pin:unapproved` | **hidden**; `pin.unapproved` / `pin:unapproved` |
| pending | set `approved`, visible, `pin_event` | visible; `pin.unapproved` / `pin:unapproved` | **hidden**; `pin.unapproved` / `pin:unapproved` |
| approved, unchanged | visible | visible | visible |
| approved, changed | re-pin `approved`, visible, `pin_event` | visible; `pin.changed` / `pin:changed` | **hidden**; `pin.changed` / `pin:changed` |
| rejected (changed or not) | **stays rejected**; visible; `pin.rejected` audited | visible; `pin.rejected` / `pin:unapproved` | **hidden**; `pin.rejected` / `pin:unapproved` |
| duplicate name in listing | not pinned; `pin.duplicate_name` | visible; `pin.duplicate_name` / `pin:duplicate_name` | **all copies hidden**; `pin:duplicate_name` |
| any visible state + high finding not in `findings_at_approval` | unchanged | visible; analyzer's control | **hidden**; analyzer's control |

The same table applies to metadata, with "hidden" meaning "reduced" (AC-13). Duplicate names don't apply to metadata.

**Normalization, staleness, and re-check** (clock injected for deterministic tests, NFR-008):
- `ttl := normalize(ttlMs)`: missing, ≤ 0, non-integer, non-finite, or > 2^31 → none. Across pages, take the minimum valid value.
- `stale := listChangedSeen || age > (ttl != none ? min(ttl, maxAge) : maxAge) || storeIdentityChanged(dev, inode, size, mtime)`
- `allowRecheck := (listChangedSeen && now - lastRecheck >= 1s) || (!listChangedSeen && now - lastRecheck >= minAge)`
- `enforce` and `stale` and `!allowRecheck` → block (`pin.recheck_pending`, AC-17a).
- Gateway-originated requests copy `_meta` `protocolVersion` and `clientCapabilities` from the triggering client request (AC-15a). They time out after `gateway_request_timeout` (10 s, AC-15b). A `tools/list` re-check stops at 100 pages or 16 MiB (AC-15c).

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1, AC-1a, AC-2, AC-3 | Unit: golden fingerprints; property test mutating one leaf at a time (tool objects and whole discover/initialize results, including unknown `_meta` keys); volatile members ignored; duplicate names on one page and across pages | `internal/registry/fingerprint_test.go`, `internal/registry/duplicates_test.go` |
| AC-4, AC-5 | Unit: digest mismatch → all `changed`; unpinned detection table (`npx pkg`, `@latest`, `@next`, `@^1`, `@1.x`, `@1.2.3`, `@1.2.3-rc.1`; `uvx pkg`, `pkg==1.2.3`; `docker run img:tag`, `img@sha256:…`) | `internal/registry/identity_test.go`, `internal/state/identity_test.go` |
| AC-6, AC-7, AC-8 | Unit and integration: atomic write and crash simulation; 8 concurrent writers; fuzzed MCP sequences in `warn`/`enforce` never change status | `internal/registry/store_test.go` |
| AC-9–AC-14 | Exhaustive table test of `Decide` (totality); `learn` never changes `rejected`; `findings_at_approval` matching; integration through `bulwark wrap` (filtering, pagination, `-32602`, reduced metadata with 128-character caps, stub analyzer) | `internal/registry/modes_test.go`, `internal/proxy/pin_test.go` |
| AC-14a | Integration: approval written to the store → client receives `list_changed` (legacy) or a tagged notification on an open listen stream (2026-07-28); none without a stream | `internal/proxy/notify_test.go` |
| AC-15–AC-15c | Integration: Bulwark's own discover first, carrying the client's `_meta`; discover error or timeout → reduced metadata; re-check error or timeout → call blocked; endless `nextCursor` → stops at 100 pages, call blocked | `internal/proxy/discover_test.go`, `internal/proxy/recheck_test.go` |
| AC-16–AC-18 | Unit with an injected clock: `ttlMs` of `-1`, `0`, `1`, `1.5`, `1e300`, absent, and mixed across pages; every staleness trigger; notification re-check at 1 s; age re-check at `min_age`; stale while rate-limited → `pin.recheck_pending`; a fake upstream that changes a tool without notifying | `internal/registry/view_test.go`, `internal/proxy/recheck_test.go` |
| AC-19, AC-20 | The suite (now-required cells, with the stated setups), plus the README table generated from `results.json` | `lab/suite` |
| AC-21 | The spec 002 benchmark with pinning enabled | `internal/pipeline/bench_test.go` |
| AC-22 | Diff of spec 001's AC-2 vocabulary and plan setup defaults, checked in review | spec 001 files |

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| A server legitimately reorders tools or changes `_meta` noise (for example timestamps) on every list, causing constant `changed` | Fingerprints are per tool (order doesn't matter). Noisy fields can be excluded per tool through `exclude_fields`, which is audited and visible in diffs (spec 005). README guidance |
| File locks behave differently on network filesystems | `state_dir` is documented as local-disk only; lock failure in `enforce` → refuse to start |
| Bulwark's own discover changes timing for some clients | It happens once per process, before the first forwarded request; the transparency test (spec 002 AC-6) keeps running in `learn` mode |
