# Tasks 004: Static analyzers on all channels + detection corpora

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**Corpora first, so rules are written against data**
- [ ] **T1:** `tools/corpus mcptox` (poisoned): convert `pure_tool.json` at a pinned commit to ASCII-escaped JSONL; round-trip test; count test (485). (AC-14, AC-16)
- [ ] **T2:** Clean-listing parser for `response_all.json`: tests first (single tool, arguments with and without descriptions, repeated listings, a missing name fails), then `clean.jsonl` (353 matched, 322 after the AC-14a license filter) and `tool_names.json`. (AC-14, AC-14a, AC-16)
- [ ] **T3:** Record → analyzer input mapping (clean → `Tool`, poisoned → `{name, description}`, cross-reference context), with tests. (AC-15)
- [ ] **T4:** `licenses.json` and `licenses/` (per-server URL, commit, SPDX ID; allowlist test), `NOTICE`, `source.json` (commit and file hashes), the server-grouped split (`split.json`; 20/178/156 asserted), and the CONTRIBUTING.md tuning rule. (AC-14, AC-17)
- [ ] **T5:** `corpus-provenance.yml` (weekly and dispatch, re-convert, diff); `.gitleaks.toml` allowlist scoped to `testdata/corpora/`. (AC-16a, AC-16b)

**Framework**
- [ ] **T6:** `Finding`, `Analyzer`, registry, and `analyzers.enabled`. Tests first. (AC-1, AC-13)
- [ ] **T7:** `normalize.go`: NFKC, case fold, Cf removal; tests first (fullwidth, case, zero-width-split words). (AC-3)
- [ ] **T8:** `extract.go`: a generic walk of every string and key with the skip-list; sampling `tools` routed as CH-1; `elicitation.url` finding; golden files per channel (including `const`, `examples`, prompt `resource_link`, embedded resources); JSON Pointers; excerpt redaction and escaping. (AC-1, AC-2)
- [ ] **T9:** Rule file loader (RE2 only) and the examples test. (AC-4)
- [ ] **T10:** Fingerprint-keyed cache and the 64 KiB truncation finding. (AC-5)

**Analyzers** (each: table tests first, written against the **tuning** half)
- [ ] **T11:** `unicode.hidden`, including mixed-script names (ignoring `Common`/`Inherited`; single-script non-Latin names allowed) and the L-06 payload. (AC-6)
- [ ] **T12:** `text.imperative`, with severity escalation on sensitive targets. (AC-7)
- [ ] **T13:** `text.cross_reference`, with escalation when combined with an imperative. (AC-8)
- [ ] **T14:** `schema.side_channel`: the name list with case and separator variants; escalation on soliciting descriptions. (AC-9)

**Wiring**
- [ ] **T15:** Analyzer interceptors: CH-1/CH-2 → spec 003 hook (hide/reduce unless accepted); CH-4–CH-7 → record only; `learn` doesn't accept findings. Integration tests. (AC-10, AC-11, AC-12)

**Metrics and CI**
- [ ] **T16:** `corpus_test.go`: held-out metrics with Wilson intervals, per analyzer (`not measured` where AC-15 says so), paradigm, and risk; `report.json`. (AC-18)
- [ ] **T17:** Initial `baseline.json` from the first full held-out run; the point-value ratchet; the `meta` `baseline-change:` check. (AC-19)
- [ ] **T18:** `tools/ci-summary`: the corpus section in the job summary. (AC-18)

**Suite, docs, performance**
- [ ] **T19:** The `meta` check against changing both a payload and `rules.yaml` in one PR. Update the L-01, L-03, L-05, L-06, L-07 manifests per AC-21 (drop `pending: spec-004`; use `known_gap` for any frozen payload that isn't detected, **never** tuning rules to a payload). The suite must pass on Linux and macOS. (AC-20, AC-21)
- [ ] **T20:** README: results-table cells, the metrics table with targets and current values, and the honest note on what an analyzer does and doesn't stop. (AC-19, AC-21a)
- [ ] **T21:** Benchmarks: the cached gate still passes; cold per-tool time reported. (AC-22)
- [ ] **T22:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`.

**Amendment (decision 43):** T1–T4 write the corpus files to `testdata/corpora/.cache/` (git-ignored) and commit only `source.json` (download and converted-file SHA-256s), `licenses.json`, `NOTICE`, and `baseline.json`; add the CI `corpus` job and the no-tracked-`*.jsonl` test (AC-13a). The `licenses/` texts and the `testdata/corpora/` gitleaks allowlist are dropped.
