# Tasks 004: Static analyzers on all channels + detection corpora

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**Corpora first, so rules are written against data**
- [ ] **T1:** `tools/corpus mcptox`: convert `pure_tool.json` at a pinned commit to ASCII-escaped JSONL; round-trip test (decoding reproduces source strings exactly); count test (485). (AC-14, AC-16)
- [ ] **T2:** MCPTox `NOTICE` with every required attribution element, and a test that checks for each element. (AC-14)
- [ ] **T3:** `tools/corpus benign`: run the reference servers, capture `tools/list`, record versions; ASCII escaping; count test (≥ 100); `NOTICE`. (AC-15, AC-16)
- [ ] **T4:** Fixed split (`split.json`) with a test; CONTRIBUTING.md rule: tune on the tuning half only. (AC-17)

**Framework**
- [ ] **T5:** `Finding`, `Analyzer`, registry, and `analyzers.enabled`. Tests first. (AC-1, AC-13)
- [ ] **T6:** `normalize.go`: NFKC, case fold, Cf removal; tests first (fullwidth, case, zero-width-split words). (AC-3)
- [ ] **T7:** `extract.go`, per channel, with golden files (nested schemas, `$defs`, `enum`, `default`); JSON Pointers; excerpt redaction and escaping. (AC-1, AC-2)
- [ ] **T8:** Rule file loader (RE2 only) and the examples test. (AC-4)
- [ ] **T9:** Fingerprint-keyed cache and the 64 KiB truncation finding. (AC-5)

**Analyzers** (each: table tests first, written against the **tuning** half)
- [ ] **T10:** `unicode.hidden`, including mixed-script names and the L-06 payload. (AC-6)
- [ ] **T11:** `text.imperative`, with severity escalation on sensitive targets. (AC-7)
- [ ] **T12:** `text.cross_reference`, with escalation when combined with an imperative. (AC-8)
- [ ] **T13:** `schema.side_channel`: the name list with case and separator variants; escalation on soliciting descriptions. (AC-9)

**Wiring**
- [ ] **T14:** Analyzer interceptors: CH-1/CH-2 → spec 003 hook (hide/reduce unless accepted); CH-4–CH-7 → record only; `learn` doesn't accept findings. Integration tests. (AC-10, AC-11, AC-12)

**Metrics and CI**
- [ ] **T15:** `corpus_test.go`: held-out metrics per analyzer, paradigm, and risk; `report.json`. (AC-18)
- [ ] **T16:** Initial `baseline.json` from the first full held-out run, and the ratchet check. (AC-19)
- [ ] **T17:** `tools/ci-summary`: the corpus section in the job summary. (AC-18)

**Suite, docs, performance**
- [ ] **T18:** Update the L-01, L-03, L-05, L-06, L-07 manifests per AC-20 (drop `pending: spec-004`). The suite must pass on Linux and macOS. (AC-20)
- [ ] **T19:** README: results-table cells, the metrics table with targets and current values, and the honest note on what an analyzer does and doesn't stop. (AC-19, AC-21)
- [ ] **T20:** Benchmarks: the cached gate still passes; cold per-tool time reported. (AC-22)
- [ ] **T21:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`.
