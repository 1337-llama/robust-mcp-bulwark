# Tasks 005: `tools` CLI

Each task takes under about an hour and can be verified on its own. The test is written before the implementation.

**Observation file**
- [ ] **T1:** `observed.go`: format, atomic locked save, bounds (1,000 tools, 16 MiB, `limit_exceeded`). Tests first. (AC-1, AC-3)
- [ ] **T2:** Pin interceptors write observations in `warn`/`enforce` and never touch the pins file outside `learn`; a byte-equality test on the pins file. (AC-2)

**State and diff**
- [ ] **T3:** `state.go`: the state table from plan.md as a table test, then the implementation. (AC-4)
- [ ] **T4:** `internal/diff`: structural JSON diff with JSON Pointer paths and a line diff for long strings; golden tests first. (AC-6)

**Commands**
- [ ] **T5:** `tools list` (text and `--json`), with golden tests for every state and exit codes 0/3. (AC-4, AC-5)
- [ ] **T6:** `tools diff` for a tool and for `--metadata`, ending with the exact approve command; hostile-string golden test through `termsafe`. (AC-6, AC-7, AC-8, AC-13)
- [ ] **T7:** `tools approve --fingerprint`: the locked transaction, the stale-fingerprint refusal (exit 3), `findings_at_approval`. Tests first. (AC-9, AC-13)
- [ ] **T8:** Interactive approval through a pseudo-terminal (type 8 hex digits); non-interactive refusal (exit 2). (AC-10)
- [ ] **T9:** `--all` guard rails (`--yes-i-reviewed` + `--fingerprints FILE`). (AC-11)
- [ ] **T10:** `tools reject` for a tool and for `--metadata`. (AC-12, AC-13)
- [ ] **T11:** CLI audit chain records, verified by `audit verify`. (AC-14)
- [ ] **T12:** Permission checks and refusal; confirm no network access. (AC-16, AC-17)

**Integration**
- [ ] **T13:** Live approval: gateway in `enforce`; approve; the client sees the tool within about 1 s, and gets a notification with a listen stream. (AC-15)
- [ ] **T14:** The suite's setup uses an observation pass (analyzers off) and `tools approve --fingerprint`; test that seeded pins accept no findings; the suite passes. (AC-18)

**Close-out**
- [ ] **T15:** DESIGN.md §6.1/§6.4 and README (operator workflow: `list` → `diff` → `approve --fingerprint`). (docs)
- [ ] **T16:** Demonstrate every acceptance criterion with evidence in the PR; set status to `Done`.
