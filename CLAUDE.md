# Instructions for Claude: MCP Bulwark

A security gateway for MCP. It acts as a server to agents and as a client to upstream servers. It pins and inspects tool definitions, enforces policy-as-code on tool calls, tracks session taint to contain exfiltration, and writes hash-chained audit logs. The process is described in `docs/WORKFLOW.md`: **Idea → Design → Specs → Build → Release**.

## Current stage
**Stage 0 → 1.** `IDEA.md` is in its final stress test, then design work begins at `DESIGN.md` §1–§2. **No implementation code yet.** The roadmap is lab-first ([ADR-0001](docs/adr/0001-lab-first-roadmap.md)), so the first specs are 001 (attack lab) and 002 (benchmark harness).

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
- **Work one section at a time.** Before filling a section, read `IDEA.md`, the related sections, and the ADRs in `docs/adr/`. Then ask the maintainer the section's "Questions to resolve", up to about 5 at a time, each with your recommended answer, before writing.
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
