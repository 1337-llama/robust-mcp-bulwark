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

**Decision table** (`modes.go`, tested exhaustively):
| Mode | Pin state | Action | Finding / control |
|---|---|---|---|
| `learn` | missing or changed | pin as `approved`, visible | `pin_event` |
| `warn` | missing | visible | `pin.unapproved` / `pin:unapproved` |
| `warn` | changed | visible | `pin.changed` / `pin:changed` |
| `warn` | rejected | visible | `pin.unapproved` / `pin:unapproved` |
| `enforce` | missing, pending, rejected | **hidden** | `pin.unapproved` / `pin:unapproved` |
| `enforce` | changed | **hidden** | `pin.changed` / `pin:changed` |
| `enforce` | approved + high finding | **hidden** | the analyzer's control |
| any | approved, unchanged, no high finding | visible | none |

The same table applies to metadata, with "hidden" meaning "stripped" (AC-13).

**Staleness and re-check:**
- `stale = listChangedSeen || (ttl > 0 && age > min(ttl, maxAge)) || (ttl == 0 && age > maxAge) || storeMTimeChanged`
- `allowRecheck = now - lastRecheck >= minAge`

The clock is injected for deterministic tests (NFR-008).

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1, AC-2, AC-3 | Unit: golden fingerprints; every field changes the fingerprint (property test that mutates one leaf at a time); `exclude_fields` behavior | `internal/registry/fingerprint_test.go` |
| AC-4, AC-5 | Unit: digest mismatch → all `changed`; unpinned `npx`/`uvx`/`docker` detection table | `internal/registry/identity_test.go`, `internal/state/identity_test.go` |
| AC-6, AC-7, AC-8 | Unit and integration: atomic write and crash simulation (temporary file left behind); 8 concurrent writers; no status change from MCP traffic in `warn`/`enforce` (fuzzed message sequences) | `internal/registry/store_test.go` |
| AC-9–AC-14 | Table test of `Decide`; integration through `bulwark wrap` with a fake upstream for list filtering, pagination, `-32602`, metadata stripping, and the stub analyzer | `internal/registry/modes_test.go`, `internal/proxy/pin_test.go` |
| AC-15 | Integration: client sends `tools/list` first under 2026-07-28 → Bulwark's own discover is observed upstream first, and its response is not forwarded | `internal/proxy/discover_test.go` |
| AC-16–AC-18 | Unit with an injected clock: every staleness trigger; the `min_age` rate limit; `ttlMs: 0`; `ttlMs: 1`; integration with a fake upstream that changes a tool without notifying | `internal/registry/view_test.go`, `internal/proxy/recheck_test.go` |
| AC-19, AC-20 | The suite (now-required cells), plus the README table generated from `results.json` | `lab/suite` |
| AC-21 | The spec 002 benchmark with pinning enabled | `internal/pipeline/bench_test.go` |

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| A server legitimately reorders tools or changes `_meta` noise (for example timestamps) on every list, causing constant `changed` | Fingerprints are per tool (order doesn't matter). Noisy fields can be excluded per tool through `exclude_fields`, which is audited and visible in diffs (spec 005). README guidance |
| File locks behave differently on network filesystems | `state_dir` is documented as local-disk only; lock failure in `enforce` → refuse to start |
| Bulwark's own discover changes timing for some clients | It happens once per process, before the first forwarded request; the transparency test (spec 002 AC-6) keeps running in `learn` mode |
