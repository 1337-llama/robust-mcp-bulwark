# Tasks 006: Policy engine, argument roles, MRTR checks, `policy test`

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**Engine**
- [ ] **T1:** Add OPA (pinned) to `go.mod`; set `go 1.26`. Golden test of the 11 removed built-ins; `http.send` fails to load. (AC-1, AC-2)
- [ ] **T2:** `schemas/policy-input.v1.json` (`additionalProperties: false`) and compilation with `rego.Schemas`; a typo'd field fails to load. (AC-3)
- [ ] **T3:** `Load` from `policy.dirs` (skipping `_test.rego`) plus the embedded baseline; `wrap` exits 1 on a load error in every mode. (AC-1, AC-4, AC-7)
- [ ] **T4:** `Decide`: combiner table test first, then the deadline, `eval_error`, `timeout`, and non-string entries → `policy:default-deny`. (AC-5, AC-6)

**Decision input**
- [ ] **T5:** `input.go`: derived-value table tests for the three roles (including arrays and `null` cases), then the builder; config rejects unknown roles. (AC-9, AC-10, AC-11)
- [ ] **T6:** Policy interceptor: deny text in `enforce`, forward with controls in `warn`/`learn`, `approval_required`; Go SDK client sees `IsError`. (AC-8)

**MRTR**
- [ ] **T7:** `internal/mrtr/table.go` with an injected clock: record, TTL, eviction, match rules, ambiguity, single use. (AC-13, AC-14)
- [ ] **T8:** MRTR interceptor: `unmatched_retry`, `unsolicited_response`, block forms for all three methods (`-32011` for prompts and resources), `mrtr.mode: audit`; a `tools/call` retry continues to policy with `is_retry`; `requestState` bytes unchanged. (AC-15, AC-16)

**CLI and examples**
- [ ] **T9:** `bulwark policy test` (tester runner with the gateway's capabilities, schema, and baseline; exit 0/3/1) and `--input`. (AC-17, AC-18)
- [ ] **T10:** `examples/policies/` with the three §5.6 rules and tests, plus the inline-form fixture; CI step. (AC-12, AC-19)

**Suite, performance, close-out**
- [ ] **T11:** `lab/policies/` templates (one rule each); remove `pending: spec-006` from L-01, L-03, L-04 run 1, and L-08 run 2; the suite passes on Linux and macOS. (AC-20)
- [ ] **T12:** Benchmark with policy enabled; the gate still passes. (AC-21)
- [ ] **T13:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`.
