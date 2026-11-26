# Agent Firewall: Idea Brief

| Field | Value |
|---|---|
| Status | Draft |
| Theme | Securing AI |
| Working name | Agent Firewall (placeholder; check for collisions before publishing) |
| Last updated | 2026-11-26 |

## Elevator pitch

Agent Firewall is a **security gateway that sits between AI agents and the MCP servers that give them tools**. It pins and inspects every tool definition, enforces least-privilege policy-as-code on every tool call, tracks untrusted data through an agent session to block exfiltration paths, and writes a tamper-evident audit trail. It is a drop-in proxy: point the agent at the gateway instead of the server.

## Problem

AI agents are increasingly given real capabilities through the Model Context Protocol (MCP): file systems, shells, email, ticketing, cloud APIs. This creates a new attack surface that existing security controls don't see:

- **Tool definitions are an injection channel.** Tool names, descriptions, and schemas go straight into the model's context. A malicious or compromised server can hide instructions there (*tool poisoning*). The user never sees them, but the model follows them.
- **Approval is one-time and trust is permanent.** Users approve a server once. Its tool definitions can change later (*rug pull*), and nothing alerts anyone.
- **Tool outputs are untrusted input.** Content returned by a web-fetch or email-read tool can carry indirect prompt injection that hijacks the agent's next action.
- **Exfiltration is easy once three conditions meet:** access to private data, exposure to untrusted content, and a tool that can communicate externally (the "lethal trifecta", a term coined by Simon Willison). Most agent setups have all three in one session.
- **No authorization or audit at the tool boundary.** Organizations rarely have an inventory of which agents can call which tools with which arguments, and they rarely have a reliable record of what agents actually did.

Most existing defenses are either **static scanners** run at install time, or **content guardrails** on chat prompts. Neither enforces policy on each tool call at runtime.

## Why now

- Demand for AI Security Engineers grew **268%** year over year (CyberSN data via SecurityWeek, 2026). Hands-on experience with AI agents is the competency hiring leaders say is hardest to find (Cisco, 2026).
- OWASP published the **Top 10 for Agentic Applications** (December 2025) and the **2026 Top 10 for LLM Applications** (August 2026). Prompt injection is still #1.
- 2026 academic research found that most major MCP clients have significant weaknesses in validating tool definitions (arXiv 2603.22489). The Cloud Security Alliance published a whitepaper on tool poisoning and rug pulls (May 2026).

## Target users

| Persona | Need | How they use it |
|---|---|---|
| **Platform/AppSec engineer** (primary) | Roll out agents across the org without granting unlimited tool access | Deploys the gateway centrally, writes policies, reviews tool-change alerts |
| **Developer using coding agents** | Use third-party MCP servers locally without being compromised | Runs the gateway locally as a wrapper around stdio servers |
| **SOC / IR analyst** | Investigate what an agent did during an incident | Queries audit logs, consumes alerts in the SIEM |
| **GRC / auditor** | Evidence that agent access is controlled and logged | Reads policy files and audit exports (feeds AI Compliance-as-Code) |

## Vision (12 months)

The default open-source way to put a security boundary around agent tool use. It ships with a policy library for common servers and a published benchmark showing attack success rates with and without the gateway. It integrates cleanly with SIEMs and identity providers.

## Goals

- **G1 Drop-in.** Adoption requires changing one line of agent configuration, with no changes to agents or servers.
- **G2 Tool integrity.** Detect tool poisoning in definitions and detect any definition change after approval (rug pull).
- **G3 Least privilege.** Enforce allow/deny/ask decisions per tool call, including constraints on arguments, written as policy-as-code.
- **G4 Break the trifecta.** Track untrusted and sensitive data through a session. Block or escalate egress-capable tool calls once a session is tainted.
- **G5 Accountability.** Write a tamper-evident, SIEM-friendly audit record of every tool interaction.
- **G6 Low overhead.** Add negligible latency on the fast path (see success metrics).
- **G7 Proven effectiveness.** Publish a reproducible benchmark with malicious MCP servers and real agents.

## Non-goals

- **NG1** Not a general LLM content filter or chat guardrail. It works only at the tool boundary.
- **NG2** Does not claim to *prevent* prompt injection, which is an open problem. It **limits the damage** a hijacked agent can do.
- **NG3** Not a full data loss prevention (DLP) product. Secret and PII detection is best-effort.
- **NG4** Does not defend against a compromised agent host, or agents that bypass the gateway. Network controls handle bypass and are documented as a deployment requirement.
- **NG5** Not an MCP server registry or marketplace.

## Scope

> **Build order is lab-first.** Attacks come before defenses. The attack lab and a baseline benchmark with no protection come first, and they become the project's first public write-up. The gateway is then built and measured against the same attacks. See DESIGN.md §12.

### MVP (v0.1)
- Proxying for **stdio** and **Streamable HTTP** MCP transports
- Tool inventory with **fingerprinting and pinning**; CLI to review diffs and approve
- **Static analyzers** for tool definitions: hidden Unicode, instruction-like text, references to other tools, sensitive paths, schema anomalies
- **Policy engine** on `tools/call`: allow / deny / require-approval, with argument constraints
- **Secret redaction** in tool arguments and results
- **Audit log**: JSONL with a hash chain
- **Attack lab**: deliberately malicious (but harmless) MCP servers for demos and tests

### Later (v0.2+)
- Session **taint tracking** and information-flow policies (G4)
- ML **prompt-injection classifier** for tool results and descriptions
- **Human-in-the-loop approval** broker
- OpenTelemetry traces and OCSF-formatted export for SIEMs
- Identity propagation through OAuth 2.1 (per-user and per-agent principals)
- Policy library for popular servers; web dashboard
- Public benchmark report; Kubernetes/Helm deployment

## Key capabilities

1. **Pin and diff.** A hash of every tool definition is recorded at approval. Any change quarantines the tool and shows a readable diff.
2. **Inspect.** Layered detectors score definitions and results. Scores feed into policy decisions rather than acting as a black-box block.
3. **Decide.** Policy-as-code (Cedar or OPA, decided by ADR) evaluates *who* is calling *which tool* with *which arguments*, given the session's *taint state*.
4. **Contain.** Egress-capable tools are restricted once a session has seen both sensitive data and untrusted content.
5. **Record.** A tamper-evident log of every decision, with the reasons and policy IDs behind it.

## Prior art and differentiation

| Existing tool / approach | What it does well | Gap this project fills |
|---|---|---|
| Static MCP scanners (for example Invariant's MCP-Scan, now part of Snyk; `mcpscan`) | Install-time detection of poisoned descriptions; tool pinning | Do not enforce policy on each call at runtime or track information flow; limited audit |
| LLM guardrails (for example Llama Guard / Prompt Guard models, NeMo Guardrails) | Classify prompts and responses | Not aware of MCP semantics; no per-tool authorization or pinning |
| Commercial / vendor MCP gateways (for example Docker MCP Gateway) | Server lifecycle, isolation, catalogs | `VERIFY:` survey their security features. Expected gap: open, policy-as-code, taint-aware enforcement with a public benchmark |
| API gateways / WAFs | Mature traffic control | Do not understand JSON-RPC/MCP or model-facing content |
| Research: CaMeL (Google DeepMind, 2025), "lethal trifecta" | Principled information-flow defenses | Research prototypes; this project brings a practical, simplified version to a deployable gateway |

> Before the design is frozen, do a fresh prior-art survey (search GitHub and vendor sites for "MCP gateway", "MCP proxy", and "MCP firewall") and update this table.

## Success metrics

| Metric | Target (initial; refine in design) | How measured |
|---|---|---|
| Attack success rate (ASR) reduction | ≥ 80% relative reduction across the lab scenarios | Benchmark harness with a real agent, with and without the gateway |
| Poisoning detector recall / false positive rate | ≥ 90% recall on lab corpus; ≤ 2% FPR on a benign corpus of popular real servers | Analyzer test suite |
| Rug-pull detection | 100% of definition changes detected | Lab scenario tests |
| Latency overhead (excluding upstream and ML classifier) | p95 < 5 ms per message | Load test |
| Time to adopt | < 10 minutes from install to first protected session | Documented quickstart, timed |

## What this project demonstrates

| Area | Evidence in this project |
|---|---|
| Security depth | Threat modeling of a new protocol, OWASP Agentic/LLM mapping, information-flow control, tamper-evident logging, red-team lab |
| AI/ML engineering | Prompt-injection classification, evaluation with recall/FPR/ASR, understanding how agents fail |
| Software engineering | High-performance protocol proxy, policy engine integration, plugin architecture, load testing, single-binary distribution |
| Engineering leadership | Phased roadmap, ADRs, explicit non-goals, public benchmark methodology, contributor-ready repo |

## Risks and open questions

- **R1** The MCP spec changes quickly (transports, auth, new methods). *Mitigation:* pin a spec revision and keep protocol handling behind an adapter layer.
- **R2** False positives in detectors cause alert fatigue. *Mitigation:* scores feed policy; modes are `learn` / `warn` / `enforce`.
- **R3** Human approval can itself be exploited (approval fatigue, misleading approval prompts). *Mitigation:* rate limits, clear diffs, approve by policy rather than by individual call.
- **Q1** Go or Python for the core? (Go suits a fast single-binary proxy; Python has the ML ecosystem.) Possibly a Go core with a Python classifier sidecar.
- **Q2** Cedar or OPA/Rego for policy?
- **Q3** How should the calling principal be identified over stdio, where there is no auth layer?
- **Q4** How should server-initiated requests (sampling, elicitation) be handled? Are they in scope for the MVP?
- **Q5** Which classifier: a small open model run locally, an LLM-as-judge, or both in tiers?

## Maintainer notes

<!-- Add your own experience, opinions, and edits here. For example: real-world agent rollouts you've seen, which attacks matter most to enterprises, how you would pitch this to a CISO. -->
