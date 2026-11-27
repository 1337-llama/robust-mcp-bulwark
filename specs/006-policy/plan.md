# Plan 006: Policy engine, argument roles, MRTR checks, `policy test`

## Approach
This implements DESIGN.md §5.6 and §5.7 on top of spec 002's pipeline. Two interceptors join the `tools/call` chain in the §5.1 order: the MRTR check first, then the policy last. The engine is a thin wrapper around OPA's `rego` package. Everything OPA already does, it delegates to OPA: sandboxing (capabilities), type-checking policies against the input schema (`rego.Schemas`), and running tests (`v1/tester`). Bulwark adds only the input builder, the derived values, the combiner, and the MRTR table.

**Verified on 2026-11-27 against OPA v1.22.4** (a scratch Go program, not committed):
- Removing the built-ins marked `nondeterministic` from `ast.CapabilitiesForThisVersion()` drops 11. A query using `http.send` then fails to load.
- With strict built-in errors on, a helper-rule restriction (`some p in input.derived.fs_path; not path_ok(p)`) denies for a `null` element. The inline form `not r.domain in {...}` does **not**: the undefined reference makes the whole rule body undefined.
- An invalid regex inside a `deny` rule makes evaluation fail, so the call is denied (fail closed).
- `rego.Schemas` with an `additionalProperties: false` schema rejects `input.derived.fs_paht` at prepare time.

## Modules and files
| Path | New/Changed | Responsibility |
|---|---|---|
| `internal/policy/engine.go` | New | Load, capabilities, schema, prepare, evaluate with a deadline, combine (AC-1–AC-8) |
| `internal/policy/baseline.rego` | New | `allow contains "baseline-approved-tool"` (AC-7), embedded with `go:embed` |
| `internal/policy/input.go` | New | Decision input and derived values (AC-9–AC-11) |
| `schemas/policy-input.v1.json` | New | The input schema, used by `rego.Schemas` and in tests (AC-3, AC-9) |
| `internal/mrtr/table.go` | New | Bounded TTL table, matching, single use (AC-13, AC-14) |
| `internal/pipeline/mrtr_interceptor.go`, `policy_interceptor.go` | New | Checks, block forms, audit fields (AC-8, AC-15, AC-16) |
| `cmd/bulwark/policy.go` | New | `policy test`, `--input` (AC-17, AC-18) |
| `examples/policies/` | New | Three rules + `_test.rego` (AC-19) |
| `lab/policies/l01-…`, `l03-…`, `l04-….rego.tmpl` | New | One rule each (AC-20) |
| `lab/scenarios/L-01/03/04/08.yaml` | Changed | Remove `pending: spec-006` from the runs in AC-20 |

## Interfaces and data structures
```go
// internal/policy
type Decision struct {
	Outcome  string   // "allow" | "deny" | "approval_required"
	Controls []string // sorted; "policy:<id>" or "policy:default-deny"
	Reason   string   // "" | "eval_error" | "timeout"
}

func Load(dirs []string, baselineAllow bool) (*Engine, error) // AC-1–AC-4, AC-7
func (e *Engine) Decide(ctx context.Context, in Input) Decision // AC-5, AC-6; never returns an error

const query = "data.bulwark.authz" // one evaluation returns the whole package document
```
`Decide` reads the `deny`, `ask`, and `allow` keys of the result. A missing key counts as an empty set, and so does an empty result set (no modules loaded), which leads to `policy:default-deny`. Other keys (helper rules) are ignored. This was verified on v1.22.4: a package with only a `deny` rule returns `{deny: [...], helper: ...}`; with no modules, the result set is empty.

**MRTR table entry:** `{method, target, requestState *string, keys map[string]struct{}, at time.Time}`; at most 64, oldest evicted first, TTL 10 minutes. The gateway runs one process per wrapped server, so the server is implicit.

**Error form added to DESIGN.md §6.6:** a blocked MRTR retry on `prompts/get` or `resources/read` → JSON-RPC error `-32011` (implementation-defined range), message `Blocked by MCP Bulwark (<control>)`. The existing policy-deny row changes its text from `(policy <id>)` to `(<control>)`, so every block names its control ID the same way.

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1–AC-4 | Unit: load from dirs (skip `_test.rego`); golden list of the 11 removed built-ins; `http.send` and a schema typo fail to load; `wrap` exits 1 in every mode | `internal/policy/engine_test.go`, `cmd/bulwark/wrap_policy_test.go` |
| AC-5, AC-6 | Unit: combiner table (deny/ask/allow/none, mixed); non-string set entry → deny; an invalid regex → `eval_error`; a slow policy (a large comprehension) with a 1 ms deadline → `timeout` | `internal/policy/engine_test.go` |
| AC-7, AC-8 | Unit and integration: baseline on/off; deny result text in `enforce`; forwarded with controls in `warn`; the official Go SDK client sees `IsError` | `internal/policy/engine_test.go`, `internal/proxy/policy_test.go` |
| AC-9–AC-11 | Unit: a policy reading `input.arguments.<x>` loads; table of derived values per role (absent required → `null`, absent optional → nothing; absolute/relative/NUL paths, `..`; URLs without host, uppercase host, non-ASCII host, ports; recipients with 0/2 `@`, uppercase); arrays; undeclared arguments ignored; schema validation of every built input | `internal/policy/input_test.go` |
| AC-3a, AC-12, AC-19, AC-19a | Loader rejects `allow if {...}`; `policy test` on `examples/policies/`: each rule blocks with baseline allow, reports its ID, denies on `null`; audit-mode matches stay out of `controls` | `examples/policies/*_test.rego`, `internal/policy/failclosed_test.go` |
| AC-13–AC-16 | Unit with an injected clock: record, TTL, eviction at 65, match by `requestState`, match without it (only over state-less entries), ambiguity, single use; unsolicited key; block forms for all three methods; `requestState` bytes unchanged | `internal/mrtr/table_test.go`, `internal/proxy/mrtr_test.go` |
| AC-17, AC-18 | CLI: exit codes 0/3/1; `--input` output golden, hostile strings escaped | `cmd/bulwark/policy_test.go` |
| AC-20 | The suite with the AC-20 expectations required | `lab/suite` |
| AC-21 | Benchmark with policy enabled | `internal/pipeline/bench_test.go` |

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| An operator writes the inline `not x.y in {...}` form, which doesn't fail closed | Documented in DESIGN.md §5.6 and the example policies; the fixture in AC-12 shows the difference; `policy test` is the place to catch it |
| OPA adds a new network-capable built-in in a later version | Built-ins are removed by the `nondeterministic` flag, not by a hand list, and the golden test flags any change on upgrade |
| OPA evaluation exceeds the 5 ms budget | Prepared query, one evaluation per call; the AC-21 benchmark gate |
| A server floods `input_required` results to push out real entries | Eviction only causes an honest retry to be unmatched, which blocks (fails closed); a flood of `mrtr_input_required` records is visible in the audit log |
| OPA needs a newer Go than the project used | Go ≥ 1.26 is set in `go.mod` in T1; CI's `setup-go` reads `go-version-file`, so nothing else changes |
