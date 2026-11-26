# MCP Bulwark: Idea Brief

| Field | Value |
|---|---|
| Status | Ready for design |
| Theme | Securing AI |
| Repository | `robust-mcp-bulwark` · CLI name: `bulwark` |
| Last updated | 2026-11-26 |

## Elevator pitch

MCP Bulwark is an **open, reproducible benchmark and reference defense for AI agent tool security.** It has two parts:

- **Bulwark Bench** is an attack lab plus a test harness. It measures how often AI agents are hijacked through their MCP tools, how much a given defense reduces that, and what the defense costs in normal work it blocks by mistake.
- **Bulwark Gateway** is a drop-in security proxy that serves as the reference defense. It pins and inspects tool definitions, enforces least-privilege policy on every tool call, and keeps a tamper-evident audit trail.

Everything runs **at zero cost**, on open-source software and open-weight models.

## Problem

AI agents get real capabilities (file systems, shells, email, cloud APIs) through the Model Context Protocol (MCP). This opens attack paths that existing controls don't see:

- **Tool definitions are an injection channel.** Tool names, descriptions, and schemas go straight into the model's context. A malicious server can hide instructions there (*tool poisoning*).
- **Approval is one-time.** A tool definition can change after a user approves it (*rug pull*).
- **Tool outputs are untrusted input.** Content from web pages, emails, or issues can carry indirect prompt injection.
- **Exfiltration is easy** once private data, untrusted content, and a tool that can send data out all meet in one session (the "lethal trifecta", Simon Willison).

**Defenses are multiplying, but nobody shows they work.** At least six open-source MCP security gateways appeared in 2026 (see prior art). Their effectiveness claims are self-reported. Academic benchmarks such as MCPTox and MCP-SafetyBench measure how vulnerable *models* are, not how much a *defense* helps. Nobody reports the **cost to utility**: how much legitimate work a defense breaks.

## Why now

- On the MCPTox benchmark, several popular models fell for tool poisoning in over 60% of cases, and refusals were rare (arXiv 2508.14925).
- OWASP published the **Top 10 for Agentic Applications** (Dec 2025) and the **2026 Top 10 for LLM Applications** (Aug 2026).
- Demand for AI Security Engineers grew 268% year over year (CyberSN via SecurityWeek, 2026).

## Target users

| Persona | Need | How they use it |
|---|---|---|
| **Security researcher / evaluator** (primary for Bench) | Measure agent and defense robustness objectively | Runs Bench against models and defenses; publishes results |
| **Platform / AppSec engineer** (primary for Gateway) | Put guardrails on agent tool access | Deploys Gateway; writes policies; reviews tool-change alerts |
| **Developer using agents locally** | Use third-party MCP servers safely | Wraps stdio servers with Gateway |
| **Defense / gateway authors** | Test their own tool against a neutral benchmark | Plugs their proxy into Bench's defense slot |
| **IR analyst / auditor** | Know what an agent did; evidence of control | Reads and verifies the audit log |

## Vision (12 months)

Bulwark Bench is a credible, citable way to measure MCP defenses. Results are published with full methodology and raw data, and defense authors run it themselves. Bulwark Gateway is the reference implementation that shows which defenses work, backed by numbers rather than claims.

## Goals

- **G1 Measure.** Reproducible measurement of attack success rate (ASR) and benign task success, per model and per defense.
- **G2 Defense-agnostic.** Any MCP proxy that can wrap a stdio server can be evaluated, not only Bulwark Gateway.
- **G3 Zero cost.** Development, CI, and benchmark runs require no paid services.
- **G4 Reference defense.** Gateway with tool pinning, static analyzers, per-call policy, secret redaction, and a hash-chained audit log.
- **G5 Honest publication.** Every published result includes methodology, versions, confidence intervals, and raw data.
- **G6 Safe lab.** Attack scenarios are harmless by construction and verified to be so.

## Non-goals

- **NG1** Not a solution to prompt injection. Gateway limits the damage; it does not prevent injection.
- **NG2** Not a product ranking. Third-party defenses are evaluated only with published methodology. Their maintainers are contacted before results are published, and bypasses go through coordinated disclosure (SECURITY.md).
- **NG3** Not a general LLM content filter, DLP product, or MCP server registry.
- **NG4** No paid services, hosted infrastructure, or paid API usage.
- **NG5** Does not defend against a compromised agent host or agents that bypass the gateway.

## Constraints

| Constraint | Effect on the design |
|---|---|
| **$0 budget** | Open-weight models run locally (OpenAI-compatible local servers such as Ollama). Free hosted tiers are optional, off by default, and subject to their terms of service. Only open-source dependencies; GitHub Free plan. |
| **Maintainer time: 1–2 hours/week** | Claude drafts everything; the maintainer reviews one PR per week. PRs must be reviewable in ≤ 30 minutes, with a plain-language summary and a "Decisions for you" list. |
| **Private repo until M1 write-up** | GitHub Actions minutes are limited for private repos, so heavy benchmark runs happen locally until the repo goes public. |

## Scope

> **Build order is lab-first** ([ADR-0001](docs/adr/0001-lab-first-roadmap.md)) and **evaluation-first** ([ADR-0002](docs/adr/0002-evaluation-first-positioning.md)). Bench and the baseline come first and produce the first public write-up. Gateway is then built and measured on the same benchmark.

### MVP (v0.1)
**Bench**
- Six harmless lab scenarios (L-01…L-06) as stdio MCP servers
- Agent runner: tool-calling loop against an OpenAI-compatible model endpoint (covers local servers and most free tiers)
- Defense slot: `none`, Bulwark Gateway, or any stdio-wrapping proxy
- Scoring: ASR and benign task success, with confidence intervals over repeated runs
- Run manifests (model digest, versions, seeds) and Markdown/JSON reports
- Import of a subset of MCPTox cases (license permitting)

**Gateway (stdio only)**
- Transparent stdio proxy
- Tool fingerprinting and pinning (`learn` / `warn` / `enforce`)
- Static analyzers for tool definitions
- Per-call policy with argument constraints
- Secret redaction, hash-chained audit log, CLI

### Later (v0.2+)
Streamable HTTP transport · multi-server aggregation · session taint tracking · human approval broker · ML injection classifier · OpenTelemetry/OCSF export · MCP-SafetyBench import · multi-turn scenarios · published comparisons of third-party defenses · optional frontier-model runs on free tiers

## Prior art and differentiation

| Category | Examples | Gap MCP Bulwark fills |
|---|---|---|
| Open-source MCP security gateways (2026) | MCPKernel, McpVanguard, OpenGate, Arbitus, mcp-bastion, taintmcp, mcpgate | Effectiveness claims are self-reported. **Bench measures them; Gateway is a defense with published numbers.** |
| Vendor / platform gateways | Docker MCP Gateway, IBM ContextForge, Pomerium | Focus on operations and access; security effectiveness not independently measured |
| Static scanners | MCP-Scan (now part of Snyk), mcpscan | Install-time only; no runtime enforcement |
| LLM guardrails | Prompt-injection classifier models, NeMo Guardrails | Not MCP-aware; no per-tool authorization |
| Academic benchmarks | MCPTox (AAAI), MCP-SafetyBench | Measure *models*, not *defenses*; no utility-cost measurement. **Bench reuses their cases where licenses allow.** |

> `VERIFY:` the features and licenses of each listed project before any public comparison. This table lists them as found in a November 2026 search.

## Success metrics

| Metric | Target | How measured |
|---|---|---|
| Benchmark reproducibility | A rerun of the same manifest falls within the reported 95% confidence intervals | Repeat-run test |
| Gateway ASR reduction | ≥ 80% relative reduction on lab scenarios | Bench: `none` vs. `bulwark` |
| Gateway utility cost | Benign task success drops ≤ 10 percentage points | Bench benign tasks |
| Rug-pull detection | 100% of definition changes detected | Lab scenario L-02 |
| Analyzer false positive rate | ≤ 2% on a benign corpus of real servers' tool definitions | Analyzer test suite |
| Gateway latency overhead | p95 < 5 ms per message (no ML) | Load test |
| Cost | $0 | No paid service in any workflow |

## What this project demonstrates

| Area | Evidence |
|---|---|
| Security depth | Attack lab across OWASP Agentic/LLM risks, threat model of the gateway itself, coordinated-disclosure process |
| AI/ML engineering | Agent harness, statistically sound evaluation (ASR plus utility, with confidence intervals), local model operations |
| Software engineering | Protocol proxy, policy engine integration, plugin-style defense slot, reproducible runs |
| Engineering leadership | Positioning against a crowded field, explicit constraints, ADRs, phased roadmap, low-cost operation |

## Risks

- **R1 Small open models may be poor at tool use**, making results noisy. *Mitigation:* choose models with native tool-calling support, always report benign task success next to ASR, optionally add free-tier frontier models.
- **R2 The MCP spec changes quickly.** *Mitigation:* pin a spec revision; protocol handling behind an adapter layer.
- **R3 Free-tier terms of service** may restrict adversarial testing or log prompts. *Mitigation:* local models by default; check terms before using any hosted tier (`VERIFY:` per provider). Lab data is all fake.
- **R4 Comparing third-party tools** can be unfair or harmful. *Mitigation:* NG2 (published methodology, contact maintainers first, coordinated disclosure).
- **R5 Low maintainer time.** *Mitigation:* Claude drafts; small PRs; decisions default to Claude's recommendation unless the maintainer changes them.

## Questions

| # | Question | Status |
|---|---|---|
| Q-A | Positioning | **Resolved:** evaluation-first ([ADR-0002](docs/adr/0002-evaluation-first-positioning.md)) |
| Q-B | v0.1 transports | **Resolved:** stdio only; Streamable HTTP in v0.2 |
| Q-C | Reuse public benchmarks? | **Resolved:** yes, MCPTox subset in v0.1 (license permitting) |
| Q-D | Budget | **Resolved:** $0 |
| Q1 | Core language | Open (design §5, ADR) |
| Q2 | Policy engine (Cedar vs. OPA) | Open (design §5, ADR) |
| Q3 | Which local models (two vendors) | Open (design §10). Depends on Q4 |
| Q4 | Maintainer hardware for local models (GPU? RAM?) | **Open: needs maintainer input** |
| Q5 | Handling of sampling/elicitation | Open (design §1.2) |

## Maintainer notes

- Time available: 1–2 hours/week. Work arrives as PRs to review.
- Constraint: keep everything free for now.
