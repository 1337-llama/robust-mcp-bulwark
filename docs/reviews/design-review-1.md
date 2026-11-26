# Design Review 1: MCP Bulwark v0.1

| Field | Value |
|---|---|
| Document reviewed | [DESIGN.md](../../DESIGN.md) v0.10, with [IDEA.md](../../IDEA.md) and [ADR-0001…0004](../adr/) |
| Date | 2026-11-26 |
| Gate | Stage 1 exit ([WORKFLOW.md](../WORKFLOW.md#design-review-checklist)) |
| Independent reviews | Design 02 (PR #2), addressed in v0.7–v0.9. Design 03 (PR #3): 1 blocker, 6 should-fix, 5 nits, addressed in v0.11 (below) |
| Outcome | **Pass.** The design is approved when the maintainer merges design 03 |

## Checklist

| # | Item | Result | Evidence |
|---|---|---|---|
| 1 | Every FR/NFR is testable and numbered | **Pass** | 24 MVP FRs and 15 NFRs, each with a verification method (traceability table below) |
| 2 | Every component in §4 has a detailed design in §5 | **Pass** | All 17 entries in §4.2 (12 gateway packages, 5 suite components) are named in §5. Checked by script, which first missed `lab/scenarios/*.yaml` (a data directory); four names were added to §5.1 and §5.9 during this review |
| 3 | The threat model covers every trust boundary | **Pass** | TB1–TB5 all appear in §7.4; attack-suite threats in §7.5 |
| 4 | Every AI component has evaluation, failure modes, and a non-AI fallback | **Pass (not applicable to v0.1)** | v0.1 contains no AI model. The v0.3 classifier plan in §8 already lists evaluation, failure modes, and fallback |
| 5 | Every NFR has a way to measure it in §10 | **Pass** | All 15 NFRs are named in §10. NFR-001 and NFR-002 were linked to the new `meta` CI job during this review |
| 6 | Non-goals explicit; MVP fits the milestone plan | **Pass** | IDEA.md NG1–NG5; §12 M1–M3 cover all 8 v0.1 specs; §12.1 gives the estimate and an ordered cut line |
| 7 | Alternatives documented for each major decision | **Pass** | §13 covers 18 decision areas; ADR-0002…0004 cover the largest three |
| 8 | No `VERIFY:` items; standards cited with version and ID | **Pass** | Zero open markers in DESIGN.md and the ADRs. All were resolved on 2026-11-26 against primary sources (below) |
| 9 | Spec backlog covers the MVP completely | **Pass** | Every MVP FR and every NFR maps to one of specs 001–008 (checked by script) |

## Facts checked against primary sources (2026-11-26)

| Fact | Source |
|---|---|
| MCP 2026-07-28 handshake removal, `_meta` keys, `server/discover` fields, MRTR rules, `subscriptions/listen`, stdio framing, error code -32022 | Official changelog, `schema.ts`, and the stdio, MRTR, `server/discover`, and tools pages in github.com/modelcontextprotocol/modelcontextprotocol |
| Tool error forms (`-32602` vs. `isError`) | MCP 2026-07-28 tools page; Go SDK v1.7.0 `mcp/server.go` |
| Go SDK revision support and legacy negotiation | Go SDK v1.7.0 `mcp/shared.go` and `mcp/client.go` |
| OWASP Agentic Top 10 IDs and titles (ASI01–ASI10) | OWASP GenAI Security Project corpus repository, manifest for the 2026 final document |
| OWASP LLM Top 10 2026 (LLM01–LLM10) | GenAI-Security-Project/GenAI-LLM-Top10 README |
| ATLAS AML.T0010, AML.T0011.002, AML.T0051.001, AML.T0086 | mitre-atlas/atlas-data, ATLAS v5.6.0 |
| OCSF API Activity = class 6003 | ocsf/ocsf-schema (`api_activity.json`, `categories.json`) |
| OPA nondeterministic built-ins (11) | open-policy-agent/opa `capabilities.json` (`main`) |
| MCPTox data license (CC BY 4.0) | zhiqiangwang4/MCPTox-Benchmark `LICENSE` |
| Reference servers license (MIT, moving to Apache-2.0) | modelcontextprotocol/servers `LICENSE` |
| CaMeL citation (arXiv 2503.18813) | arXiv listing |
| Artifact attestations need a public repo on Free/Pro/Team | GitHub Docs, "Using artifact attestations" |

## Reviewer perspectives
Three roles, each giving its top three concerns. Each concern is either addressed in this version or tracked for the build.

**Staff security engineer**
1. *Same-user tampering is the largest residual risk* (AR-1, AR-2). A local server can bypass Bulwark or edit its state. **Tracked:** the README's "Limitations" section must lead with the container guidance, and spec 008's demo should show the `docker run --network none` form.
2. *The baseline allow permits any arguments to approved tools* until the operator adds `deny` restrictions. Users could believe they have argument control when they only have pinning plus the gateway's secret and MRTR checks. **Addressed:** §5.6 states this. **Tracked:** `bulwark wrap` prints a one-line notice at startup in `enforce` mode when only the baseline policy is loaded.
3. *Rule-based analyzers will be evaded* (AR-5). **Addressed:** held-out corpus metrics (§5.4), and pinning and policy work regardless of detection. **Tracked:** a "bypass reported → new corpus entry + rule" process in CONTRIBUTING.md once code exists.

**SRE**
1. *Fail-closed audit can stop an agent's work when the disk fills* (decision 33). **Accepted as designed**, because security wins in `enforce`. **Tracked:** spec 002 must make the stderr message say exactly what happened and how to recover.
2. *Several Bulwark processes for one server* (one per client window) share the pin store. **Addressed:** atomic writes and an advisory lock (§5.3). **Tracked:** spec 003 needs a concurrent-writer test.
3. *macOS CI is slower and may flake.* **Addressed:** macOS runs the suite once, and the determinism check stays on Linux (§10.2). Cut-line item 1 lets macOS move off PRs if it threatens NFR-009.

**ML engineer**
1. *v0.1 has no ML,* so the "AI" part of the portfolio rests on AI-security depth. **Accepted:** this is deliberate (ADR-0002), and the v0.3 classifier is planned to run on CPU in CI.
2. *Detection metrics could overfit to MCPTox phrasing.* **Addressed in this review:** fixed tuning and held-out split, with held-out numbers reported (§5.4).
3. *Corpus labels:* MCPTox items are labeled poisoned by construction, but the benign corpus needs care so that legitimate imperative descriptions ("Always pass absolute paths") aren't counted as attacks. **Tracked:** spec 004 defines the labeling guide for the benign corpus.

## Independent review of design 03: findings and resolution (v0.11)

| Finding | Resolution |
|---|---|
| **B1** Baseline allow overrode operator allow-rules; default-deny blocks had no control ID | Policy model changed to **allow by pin, restrict with `deny`**, with `policy:default-deny` as the default-deny control ID (§5.6, decision 35, ADR-0004 amended). Example policies rewritten as deny rules that fail closed on missing derived values. New policy tests check that restrictions block with the baseline allow enabled |
| **S1** MRTR answers on `prompts/get` and `resources/read` weren't checked | MRTR checks cover all three methods (§5.7, FR-035, decision 36); M-9 and T-16 updated |
| **S2** Mixed `location` formats | JSON Pointer everywhere (§5.6) |
| **S3** Secret denial depended on the baseline policy | Secret and MRTR blocks are gateway checks, enforced before and independent of policy (§5.5, §5.7, decision 31 amended) |
| **S4** Replay client described as using the SDK | §4.2 and A-2 corrected to raw JSON-RPC |
| **S5** `ttlMs: 1` could force a re-check per call | `pin_recheck_min_age` (default 30 s) rate-limits all re-checks (§5.3, FR-030, decision 37) |
| **S6** The traceability table satisfied the NFR-002 check by itself | The `meta` job now requires a test name or a `// Verifies:` tag (§10.2) |
| **N1** Matching a retry without `requestState` | Most recent entry with a key-superset match; ambiguous → unmatched (§5.7) |
| **N2** Exit code 70 collides with upstream codes | Bulwark failures also reported via a `bulwark:` stderr line and a `stop` audit record (§6.1) |
| **N3** Unsalted argument digests | HMAC-SHA-256 with a per-install key (§5.8, T-10, decision 38) |
| **N4** No `server_id` default in `learn`/`warn` | `auto-<12 hex of command_digest>` (§5.3) |
| **N5** Package count | Corrected to 17 (checklist item 2) |

## Requirement traceability (generated from DESIGN.md §2 and §15)

| Requirement | Spec | Verified by (§10) |
|---|---|---|
| FR-001 | 001 | suite |
| FR-002 | 001 | suite (network-isolated, syscall trace) |
| FR-003 | 001 | suite; integration |
| FR-004 | 001 | suite (attribution) |
| FR-005 | 001 | suite.yml job summary |
| FR-006 | 004 | corpus (held-out split) |
| FR-007 | 008 | release.yml scripted quickstart |
| FR-008 | 001 | unit; suite |
| FR-020 | 002 | integration; suite |
| FR-021 | 003 | unit; suite L-02 |
| FR-022 | 004 | unit; corpus; suite L-01/03/05/06 |
| FR-023 | 006 | policy; integration (error format) |
| FR-024 | 006 | policy; suite L-01/03/04 |
| FR-025 | 007 | unit; suite L-04/05/08 |
| FR-026 | 002 | unit; tamper tests |
| FR-027 | 005 | integration (CLI golden files) |
| FR-028 | 002 | property + fuzz |
| FR-029 | 002, 005 | unit (termsafe) |
| FR-030 | 003 | integration; suite L-02 |
| FR-031 | 002 | unit; fuzz |
| FR-033 | 003 | suite L-07 |
| FR-034 | 004 | unit; suite L-08 |
| FR-035 | 006 | suite L-08; integration |
| FR-036 | 002 | integration; suite (2025-11-25 subset) |
| NFR-001 | 001 | meta job |
| NFR-002 | 001 | meta job |
| NFR-003 | 001 | suite.yml (strace) |
| NFR-004 | 002 | benchmark gate |
| NFR-005 | 006 | fault injection |
| NFR-006 | 002 | tamper tests |
| NFR-007 | 002 | suite.yml (strace) |
| NFR-008 | 001 | suite run twice |
| NFR-009 | 001 | workflow timing |
| NFR-010 | 001 | macos.yml |
| NFR-011 | 008 | release.yml quickstart |
| NFR-012 | 008 | release.yml |
| NFR-013 | 002 | fuzz + limit tests |
| NFR-014 | 002 | strace + import check + policy load test |
| NFR-015 | 008 | security.yml |
