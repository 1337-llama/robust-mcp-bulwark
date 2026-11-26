# Tasks 001: Attack suite

Each task takes under about an hour and can be verified on its own. The test is written before the implementation. Each task's PR lists the acceptance criteria it covers.

**Foundation**
- [ ] **T1:** `go.mod` (current stable Go), the `lab/`, `tools/`, `.github/` skeleton; `ci.yml` `lint-test` job with `gofmt`, `go vet`, `staticcheck`, `go test`, `timeout-minutes: 10`, `permissions: contents: read`, and SHA-pinned actions. (AC-23)
- [ ] **T2:** `tools/meta labels`: test fixtures first (bad runner label, unpinned action, missing timeout), then the check; add it to the `meta` job together with `actionlint`. (AC-23, AC-25)
- [ ] **T3:** `tools/meta coverage`: test fixtures first (a `Done` spec with an uncovered ID; a covered one), then the check; add it to the `meta` job. (AC-26)

**Lab kit and binary**
- [ ] **T4:** `lab/labkit`: tests first for canary parsing, the observation-log writer (`seq` counter, JSONL), and fixture paths confined to `BULWARK_LAB_DIR`; then the implementation. (AC-3, AC-9)
- [ ] **T5:** Source-scan tests: no `net`, `net/http`, or `net/rpc` imports under `lab/`; no `time.Now` or `math/rand` in lab servers. (AC-4, AC-9)
- [ ] **T6:** `lab/cmd/bulwark-lab`: tests first (exit 2 without `BULWARK_LAB=1`; `LAB ONLY` banner; unknown subcommand error); then `main.go` with subcommand dispatch. (AC-5, AC-6)

**Manifests**
- [ ] **T7:** `lab/manifest`: strict YAML loader (unknown fields rejected), validation of control kinds and technique IDs against `allowlist.yaml`, at least one reference required. Invalid fixtures first. (AC-1, AC-2, AC-8)
- [ ] **T8:** `lab/scenarios/allowlist.yaml` with ASI01–ASI10, LLM01:2026–LLM10:2026, and the ATLAS IDs used in DESIGN.md §7.3. (AC-2)

**Replay client**
- [ ] **T9:** `lab/replay` core against an in-memory fake server: request IDs, response matching, step timeout → `timeout`, `send_raw`. Tests first. (AC-13, AC-14)
- [ ] **T10:** Revision handling: `2026-07-28` `_meta` keys on every request, no `initialize`; `2025-11-25` `initialize` + `notifications/initialized` first. Tests first. (AC-10, AC-11)
- [ ] **T11:** Steps `discover`, `list_tools` (pagination), `call` (including MRTR `input_responses` and `requestState` echo), `subscribe`, `wait_notification`; template substitution. Tests first. (AC-10, AC-11)
- [ ] **T12:** `transcript.jsonl` writer, with a completeness test (every sent and received line present, in order). (AC-12)

**Lab servers** (each: server test first, listing its tools, checking `[LAB]` and `POISON-Lxx`, and checking observation events for a scripted call)
- [ ] **T13:** `l01-notes` (L-01) and `l06-calc` (L-06). (AC-7)
- [ ] **T14:** `l02-weather` (L-02): definition change after the 2nd call; `list_changed` delivery in both revisions. (AC-7, AC-9)
- [ ] **T15:** `l03-mail` (L-03) and `l05-translate` (L-05). (AC-7)
- [ ] **T16:** `l04-web-notes` (L-04) and `l07-docs` (L-07, `ServerOptions.Instructions`). (AC-7)
- [ ] **T17:** `l08-vault` (L-08): input-required result with elicitation and `requestState`; `exfil` on a retry carrying a canary. The test asserts the exact wire format the replay client receives. (AC-7)

**Runner**
- [ ] **T18:** `lab/suite/expect.go`: observables, pending logic, control matching with `analyzer:<name>/*` patterns, tested against fixture audit logs. Tests first. (AC-16, AC-17)
- [ ] **T19:** Write the eight manifests `L-01.yaml` … `L-08.yaml` (all `bulwark-*` expectations `pending: spec-NNN` as listed in plan.md). (AC-1, AC-18)
- [ ] **T20:** `lab/suite/suite_test.go`: matrix (scenario × run × condition × revision), fresh temp directory and processes per cell, `results.json`. All `none` cells must pass. (AC-15, AC-18, AC-19)

**CI and reporting**
- [ ] **T21:** `tools/ci-summary`: golden-file test first, then the Markdown renderer. (AC-20)
- [ ] **T22:** `tools/meta trace`: parser tests on fixture `strace` output (clean; with an `AF_INET` connect), then the parser. (AC-21)
- [ ] **T23:** `suite.yml`: build, `unshare --net` + `strace`, two runs, trace check, results comparison, job summary. `macos.yml`: one run. Push and confirm both are green. (AC-20, AC-21, AC-22, AC-24)

**Close-out**
- [ ] **T24:** Fill the README results table from the CI output ("Without Bulwark" = ✅ attack works; "With Bulwark" = ⏳ pending, naming the spec); update DESIGN.md §15 if anything changed.
- [ ] **T25:** Demonstrate every acceptance criterion, with evidence (CI links, job summary) in the PR description; set this spec's status to `Done` (which turns on the AC-26 coverage check for its IDs).
