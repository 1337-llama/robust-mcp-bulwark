# Tasks 001: Attack suite

Each task takes under about an hour and can be verified on its own. The test is written before the implementation. Each task's PR lists the acceptance criteria it covers.

**Foundation**
- [ ] **T1:** `go.mod` (current stable Go), the `lab/`, `tools/`, `.github/` skeleton; `ci.yml` `lint-test` job with `gofmt`, `go vet`, `staticcheck`, `go test`, `timeout-minutes: 10`, `permissions: contents: read`, and every action SHA-pinned. (AC-23)
- [ ] **T2:** `.github/dependabot.yml`: weekly updates for GitHub Actions and Go modules. (AC-25)
- [ ] **T3:** `tools/meta labels`: test fixtures first (bad runner label; unpinned `actions/*` and third-party actions; missing timeout), then the check; add it to the `meta` job together with `actionlint`. (AC-23, AC-25)
- [ ] **T4:** `tools/meta coverage` and `tools/meta pending`: fixtures first (a `Done` spec with an uncovered ID; a `Done` spec still named in a manifest's `pending:`; passing cases), then both checks; add them to the `meta` job. (AC-26, AC-29)

**Lab kit and binary**
- [ ] **T5:** `lab/labkit`: tests first for canary parsing, the observation-log writer (`seq` counter, JSONL), and fixture paths confined to `BULWARK_LAB_DIR`; then the implementation. (AC-3, AC-9)
- [ ] **T6:** Canary shape tests: secret canaries follow the AC-31 format (`AKIAEXAMPLECANARYL<letter>Z`, key alphabet `A-Z2-7`); plain canaries match no spec 007 rule. (AC-31)
- [ ] **T7:** Source-scan tests: no direct `net`, `net/http`, or `net/rpc` imports under `lab/`; no `time.Now` or `math/rand` in lab servers. (AC-4, AC-9)
- [ ] **T8:** `lab/cmd/bulwark-lab`: tests first (exit 2 without `BULWARK_LAB=1`; `LAB ONLY` banner; unknown subcommand error); then `main.go` with subcommand dispatch. (AC-5, AC-6)

**Manifests**
- [ ] **T9:** `lab/scenarios/allowlist.yaml`: technique IDs (ASI01–ASI10, LLM01:2026–LLM10:2026, the ATLAS IDs in DESIGN.md §7.3) and the control-ID vocabulary. (AC-2)
- [ ] **T10:** `lab/manifest`: strict YAML loader (unknown fields rejected); validation of technique IDs and control IDs against the allowlist; at least one reference; `setup` validation (a non-`pin` run must approve every called tool and the metadata). Invalid fixtures first. (AC-1, AC-2, AC-8, AC-28)

**Replay client**
- [ ] **T11:** `lab/replay` core against an in-memory fake server: request IDs, response matching, step timeout → `timeout`, `send_raw`. Tests first. (AC-13, AC-14)
- [ ] **T12:** Revision handling: `2026-07-28` `_meta` keys on every request, no `initialize`; `2025-11-25` `initialize` + `notifications/initialized` first. Tests first. (AC-10, AC-11)
- [ ] **T13:** Steps `discover`, `list_tools` (pagination), `call` (including MRTR `input_responses` and `requestState` echo), `subscribe`, `wait_notification`; template substitution (`{{canaries.*}}`, `{{lab_dir}}`). Tests first. (AC-10, AC-11)
- [ ] **T14:** `transcript.jsonl` writer, with a completeness test (every sent and received line present, in order). (AC-12)

**Lab servers** (each: server test first, listing its tools, checking `[LAB]` and `POISON-Lxx`, and checking observation events for a scripted call)
- [ ] **T15:** `l01-notes` (L-01, absolute fixture paths) and `l06-calc` (L-06). (AC-7)
- [ ] **T16:** `l02-weather` (L-02): definition change after the 2nd call; `list_changed` delivery in both revisions. (AC-7, AC-9)
- [ ] **T17:** `l03-mail` (L-03) and `l05-translate` (L-05). (AC-7)
- [ ] **T18:** `l04-web-notes` (L-04) and `l07-docs` (L-07, `ServerOptions.Instructions`). (AC-7)
- [ ] **T19:** `l08-vault` (L-08): input-required result with elicitation and `requestState`; `exfil` on a retry carrying a canary. The test asserts the exact wire format the replay client receives. (AC-7)

**Runner**
- [ ] **T20:** `lab/suite/expect.go`: observables, pending logic, control matching with `analyzer:<name>/*` patterns, tested against fixture audit logs. Tests first. (AC-16, AC-17)
- [ ] **T21:** `lab/suite/setup.go`: policy template rendering, observation-pass seeding with approval (spec 005 AC-18), and generated configuration per control kind (plan.md table). Tested against a fake pin store, since the real gateway arrives in spec 002. (AC-27)
- [ ] **T22:** Write the eight manifests `L-01.yaml` … `L-08.yaml` and the lab policy templates; every `warn`/`enforce` expectation `pending: spec-NNN` as listed in plan.md. (AC-1, AC-18, AC-31)
- [ ] **T23:** `lab/suite/suite_test.go`: matrix (scenario × run × condition × revision), fresh temp directory and processes per cell, `results.json`, UID check under `CI=true`. All `none` cells must pass. (AC-15, AC-18, AC-19, AC-30)

**CI and reporting**
- [ ] **T24:** `tools/ci-summary`: golden-file test first, then the Markdown renderer. (AC-20)
- [ ] **T25:** `tools/meta trace`: parser tests on fixture `strace` output (clean; `socket(AF_INET…)`; `socket(AF_INET6…)`; interleaved PIDs; `AF_UNIX` allowed), then the parser. (AC-21)
- [ ] **T26:** `suite.yml`: build; `sudo unshare --net -- setpriv … strace …`, so the suite runs as the runner user; two runs; trace check; results comparison; job summary. `macos.yml`: one run. Push and confirm both are green. (AC-20, AC-21, AC-22, AC-24, AC-30)

**Close-out**
- [ ] **T27:** Fill the README results table from the CI output ("Without Bulwark" = ✅ attack works; "With Bulwark" = ⏳ pending, naming the spec); update DESIGN.md §15 if anything changed.
- [ ] **T28:** Demonstrate every acceptance criterion, with evidence (CI links, job summary) in the PR description. Set this spec's status to `Done`, which turns on the AC-26 coverage check and the AC-29 pending check for its IDs.
