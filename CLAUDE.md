# Instructions for Claude: MCP Bulwark

A security gateway for AI agents: an MCP proxy that pins and inspects tool definitions, enforces policy-as-code on tool calls, redacts secrets, and writes hash-chained audit logs. It ships with a deterministic **attack suite** (harmless lab servers + a scripted replay client) that proves every protection in CI ([ADR-0002](docs/adr/0002-gateway-with-attack-suite.md)). The process is described in `docs/WORKFLOW.md`: **Idea → Design → Specs → Build → Release**.

**Purpose: a portfolio project for potential employers.** Optimize for shipped, tested, well-documented software that a reviewer can evaluate in 10 minutes, not for research.

## Current stage
**Stage 2: Specs.** `DESIGN.md` v0.11 is approved (design review 1 in `docs/reviews/`). Specs are in `specs/` (index in `specs/README.md`). Under the **automated review loop** (`docs/WORKFLOW.md`, Stage 2), each spec's three files go in one PR, an independent reviewer session reviews it, and Claude merges it once no blockers remain. Claude merges only under the maintainer's standing instruction, which the maintainer can withdraw at any time. **Stop before implementation code** and check in with the maintainer. The repository is public, so CI on standard GitHub-hosted runners is free (DESIGN.md C-4).

## Working agreement (the maintainer has 1–2 hours per week)
- **Claude drafts; the maintainer decides.** Don't wait on questions. Draft complete sections, specs, or code with your recommended answers applied. Each decision stands unless the maintainer changes it in review.
- **Everything arrives as a pull request** on a branch, never pushed straight to `main`. Each PR must be reviewable in ≤ 30 minutes and start with:
  1. a plain-language summary of a few sentences (no jargon without explanation)
  2. **"Decisions for you"**: a short list of each decision made, the recommendation applied, and the alternative
  3. **"Needs your input"**: only things Claude genuinely cannot decide (money, publishing, direction, disclosure, facts about the maintainer's environment)
- **Keep everything free ($0).** No paid APIs, hosted services, or paid GitHub features.
- **No manual testing by the maintainer.** Every requirement must be verifiable by an automated test in GitHub Actions. Never design work that requires the maintainer to run models, experiments, or local tests. v0.1 needs no AI model at all.
- **Always the maintainer's call:** spending money, making the repo public, publishing write-ups, contacting other projects' maintainers, and disclosing vulnerabilities.

## Hard rules

1. **No personal information, ever.** Do not add names, employers, email addresses, locations, certifications, or biographical details to any file, commit message, issue, or PR. Refer to the owner as "the maintainer".
2. **Respect stage gates.** Do not write implementation code until `DESIGN.md` has status `Approved` and the relevant spec in `specs/` has status `Ready`.
3. **Use fictional sample data only.** Use `example.com`, RFC 5737 IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and obviously fake credentials (`AKIAEXAMPLE…`, `canary-…`).
4. **The attack lab must be harmless.** Malicious MCP servers live only in `lab/`. Each file carries a `LAB ONLY` banner, uses canary secrets only, sends "exfiltrated" data only to a local sink, and makes no external network calls. Use publicly known attack techniques. Don't write novel malware or anything aimed at real third-party systems.
5. **Use coordinated disclosure.** If benchmarking turns up a real vulnerability in a specific MCP client, server, or model product, stop and tell the maintainer. It must be reported to the vendor before any public write-up mentions it.

## Domain guardrails
- **Accuracy about the protocol is critical.** When discussing MCP methods, transports, auth, or message shapes, state which spec revision you're relying on. Mark anything uncertain `VERIFY:`. Don't invent fields or methods.
- **Enforcement is deterministic.** ML models only produce scores that feed into policy. Never design a control whose security depends on a model making the right call.
- **Be honest about limits.** MCP Bulwark limits the damage from prompt injection; it does not solve it. Never claim otherwise.
- **Keep three things separate:** threats MCP Bulwark *mitigates* (DESIGN.md §7.3), threats *to* MCP Bulwark (§7.4), and accepted risks.

## How to collaborate on the design
- **Work one or two sections per PR.** Before drafting, read `IDEA.md`, the related sections, and the ADRs in `docs/adr/`. Resolve each section's "Questions to resolve" with your recommendation and list them under "Decisions for you" in the PR.
- **Make recommendations.** State the options briefly, recommend one, and explain why. Record each resolved choice in the DESIGN.md §14 Decision Log, and write a full ADR (`templates/ADR_TEMPLATE.md`) for significant ones.
- **Write testable requirements.** Number them (`FR-001`, `NFR-001`) and make each one verifiable. Specs trace back to these IDs.
- **Cite standards precisely:** name, version, and section or ID (for example "OWASP Top 10 for LLM Applications 2026, LLM01").
- **Flag uncertainty with `VERIFY:`.** Never invent standard IDs, API names, library features, or statistics. Resolve every `VERIFY:` before the design is approved.
- **Keep it current.** Update the DESIGN.md document control table (version, date, status) on every change.

## Style
- Write concise technical prose. Prefer tables and Mermaid diagrams to long paragraphs.
- Every design choice needs a reason. "Alternatives considered" sections are required.
- Show engineering judgment: explicit non-goals, honest prior-art comparisons, measurable success criteria.

## Useful references
MCP specification (pin a revision) · OWASP Top 10 for Agentic Applications (Dec 2025) · OWASP Top 10 for LLM Applications 2026 · MITRE ATLAS · RFC 8785 · CaMeL (information-flow defense research)
