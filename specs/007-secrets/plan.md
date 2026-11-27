# Plan 007: Secret detection and redaction

## Approach
This implements DESIGN.md §5.5. A single package, `internal/redact`, holds the rules and two functions. Two interceptors use it: one scans requests before the policy, the other scans results. Nothing here is new machinery:
- the string walk is spec 004's
- the block forms are spec 006's
- message rewriting uses the same re-serialization path that spec 003 uses for reduced metadata

**Why gitleaks' patterns:** they are maintained, public, MIT-licensed, and written for Go's RE2, so they compile unchanged. Copying 7 rule groups beats inventing formats (CLAUDE.md: never invent). The rules were checked with Python's `re`, whose syntax matches here, on 2026-11-27:
- `aws-access-token` (`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`) matches the AWS documentation example `AKIAIOSFODNN7EXAMPLE`.
- It does **not** match spec 001's planned canary `AKIAEXAMPLEL04CANARY`, because that contains `0`, which isn't in the key alphabet. The canaries therefore change (below); the rule does not get looser.

## Modules and files
| Path | New/Changed | Responsibility |
|---|---|---|
| `internal/redact/rules.yaml` | New | The AC-1 regexes, with the gitleaks commit and rule IDs they came from |
| `internal/redact/redact.go` | New | `Find(s) []Match` and `Redact(s) (string, []Match)`; overlap handling (AC-7) |
| `internal/pipeline/secrets_interceptor.go` | New | Request side (AC-4), result side (AC-5), mode handling (AC-6), findings (AC-8) |
| `internal/analyzers/excerpt.go` | Changed | Calls `redact.Redact` (AC-9) |
| `internal/redact/GITLEAKS-LICENSE` | New | The MIT notice that must travel with the copied patterns |
| `lab/scenarios/L-04/05/08.yaml` | Changed | New canaries; remove `pending: spec-007` |
| spec 001 `spec.md` AC-31, `plan.md`; DESIGN.md §6.7 | Changed | Canary format (below) |

**Canary change (spec 001 AC-31):** secret canaries are `AKIAEXAMPLECANARY` + `L` + the scenario letter (`A` = L-01 … `H` = L-08) + `Z`, for example `AKIAEXAMPLECANARYLDZ` for L-04. That is 20 characters, all in the key alphabet, and still obviously fake (CLAUDE.md rule 3).

## Interfaces and data structures
```go
// internal/redact
type Match struct {
	Rule     string // AC-1 rule ID
	Severity string
	Start    int // byte offsets into the decoded string
	End      int
}

func Find(s string) []Match                // non-overlapping, after AC-7 merging
func Redact(s string) (string, []Match)    // replaces each match with "[REDACTED:<rule>]"
```
**Overlaps (AC-7):** collect the matches of every rule, sort them by start, and merge overlapping spans into one span labeled with the rule of the longest match. Ties go to AC-1 order.

**Pipeline position** (DESIGN.md §5.1): on `tools/call`, the MRTR check, the pin check, **the secret scan**, then the policy. On results, the secret scan runs before the audit record is written, so the record only ever sees redacted text.

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1 | Unit: each rule positive and negative (including `AKIAIOSFODNN7EXAMPLE`; `sk_test_…` not matched by `stripe-live-key`; a PEM block without an END line not matched); the rules file lists the gitleaks commit | `internal/redact/rules_test.go` |
| AC-2 | Unit: every manifest's `secret` canary matches `aws-access-key`; every `plain` canary matches nothing | `lab/suite/canary_test.go` |
| AC-3 | Unit: a secret in a nested argument, an object key, `structuredContent`, an error `data`, resource text, and behind a `A` escape is found; a base64 blob is not scanned | `internal/pipeline/secrets_test.go` |
| AC-4–AC-6 | Integration through `bulwark wrap`: `deny`, `redact`, and `audit` for requests; `redact` and `audit` for results; `warn` forwards requests unchanged and still redacts results | `internal/proxy/secrets_test.go` |
| AC-7 | Unit: overlapping and adjacent matches; two keys in one string; no fragment remains; a trailing `;` survives (group 1); two secret keys in one object stay distinct | `internal/redact/redact_test.go` |
| AC-8, AC-9 | After the suite: grep the audit directory and stderr captures for every secret canary → none; analyzer excerpts use `redact.Redact` | `lab/suite/leak_test.go` |
| AC-10 | The suite with the AC-10 expectations required | `lab/suite` |
| AC-11 | Benchmark | `internal/pipeline/bench_test.go` |

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| False positives on JWT-like strings in normal output | `jwt` is `medium`. Results are redacted, not blocked, and the operator can set `secrets.results: audit` |
| Redaction breaks a tool result the client parses (for example JSON inside `text`) | The marker is plain ASCII. The original is never needed downstream, and losing it is the point |
| The patterns go stale as providers change formats | Pinned to a gitleaks commit; updating is a reviewed PR that shows the upstream diff |
| Scanning large results costs time | RE2 is linear; messages are already capped at 4 MiB (spec 002); the AC-11 benchmark gate |
