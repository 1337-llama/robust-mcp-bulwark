# Instructions for Claude: Agent Firewall

Read the root `CLAUDE.md` first. Its hard rules apply here.

## Current stage
**Stage 0: Idea.** The maintainer is editing `IDEA.md`. Next comes the design (`DESIGN.md`), following `docs/WORKFLOW.md`. **No implementation code yet.**

## Project context
A security gateway for MCP. It acts as a server to agents and as a client to upstream servers. It pins and inspects tool definitions, enforces policy-as-code on tool calls, tracks session taint to contain exfiltration, and writes hash-chained audit logs.

## Domain guardrails
- **Accuracy about the protocol is critical.** When discussing MCP methods, transports, auth, or message shapes, state which spec revision you are relying on. Mark anything uncertain `VERIFY:`. Don't invent fields or methods.
- **Enforcement is deterministic.** ML models only produce scores that feed into policy. Never design a control whose security depends on a model making the right call.
- **Be honest about limits.** This project limits the damage from prompt injection; it does not solve it. Never claim otherwise in docs.
- **Attack lab rules.** Malicious MCP servers in `lab/` must be harmless: fake canary secrets, a local-only exfiltration sink, and a clear `LAB ONLY` banner in each file. They must never touch real credentials or make external network calls.
- **Keep three things separate:** threats the gateway *mitigates* (DESIGN.md §7.3), threats *to* the gateway (§7.4), and accepted risks.

## Useful references
OWASP Top 10 for Agentic Applications (Dec 2025) · OWASP Top 10 for LLM Applications 2026 · MITRE ATLAS · MCP specification · RFC 8785 · CaMeL (information-flow defense research)
