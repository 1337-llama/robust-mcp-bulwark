# Tasks 007: Secret detection and redaction

Each task takes under about an hour and can be verified on its own. The test is written before the implementation. If spec 004 is implemented first, its excerpt task (T8) uses this spec's T1–T2, so do those two first.

- [ ] **T1:** `rules.yaml` from gitleaks at the pinned commit, plus the AC-1 positive and negative tests; `GITLEAKS-LICENSE` next to it. (AC-1)
- [ ] **T2:** `Find` and `Redact` with overlap merging; tests first. (AC-7)
- [ ] **T3:** Canary check over all manifests; amend the spec 001 canaries. (AC-2)
- [ ] **T4:** Request interceptor: `deny`, `redact`, `audit`; block forms for `tools/call` and for MRTR retries; position before the policy. (AC-3, AC-4)
- [ ] **T5:** Result interceptor: `redact` and `audit` for content, `structuredContent`, errors, and resource text. (AC-3, AC-5)
- [ ] **T6:** Mode handling (`warn`/`learn` record only) and findings in audit records. (AC-6, AC-8)
- [ ] **T7:** Spec 004 excerpts call `redact.Redact`; the leak test over the audit directory and stderr after the suite. (AC-8, AC-9)
- [ ] **T8:** Remove `pending: spec-007` from L-04 run 2, L-05, and L-08 run 1; the suite passes on Linux and macOS. (AC-10)
- [ ] **T9:** Benchmark with scanning on; the gate still passes. (AC-11)
- [ ] **T10:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`.
