# MCP Bulwark: Idea Brief

| Field | Value |
|---|---|
| Status | Ready for design |
| Theme | Securing AI |
| Repository | `robust-mcp-bulwark` · CLI name: `bulwark` |
| Last updated | 2026-11-26 |

## Elevator pitch

MCP Bulwark is a **security gateway for AI agents**. It sits between an agent and the MCP servers that give it tools. It pins and inspects every tool definition, enforces least-privilege policy on every tool call, redacts secrets, and keeps a tamper-evident audit trail. It is a drop-in wrapper: `bulwark wrap -- <server command>`.

It ships with a **built-in attack suite**: deliberately malicious (harmless) MCP servers plus scripted attacks that run in CI on every change. Every security claim in the README is backed by a test that runs automatically.

## Problem

AI agents get real capabilities (file systems, shells, email, cloud APIs) through the Model Context Protocol (MCP). This opens attack paths that existing controls don't see:

- **Tool definitions are an injection channel.** Tool names, descriptions, and schemas go straight into the model's context. A malicious server can hide instructions there (*tool poisoning*).
- **Approval is one-time.** A tool definition can change after a user approves it (*rug pull*).
- **Tool outputs are untrusted input.** Content from web pages, emails, or issues can carry indirect prompt injection.
- **Exfiltration is easy** once private data, untrusted content, and a tool that can send data out all meet in one session (the "lethal trifecta", Simon Willison).
- **No authorization or audit at the tool boundary.** Few organizations control which agent may call which tool with which arguments, or keep a reliable record of what agents did.

## Why now

- On the MCPTox benchmark, several popular models fell for tool poisoning in over 60% of cases, and refusals were rare (arXiv 2508.14925). The attacks are real; this project cites that research rather than re-measuring it.
- OWASP published the **Top 10 for Agentic Applications** (Dec 2025) and the **2026 Top 10 for LLM Applications** (Aug 2026).
- Demand for AI Security Engineers grew 268% year over year (CyberSN via SecurityWeek, 2026).

## Target users

| Persona | Need | How they use it |
|---|---|---|
| **Developer using agents** (primary) | Use third-party MCP servers without being compromised | Wraps stdio servers with `bulwark wrap` |
| **Platform / AppSec engineer** | Guardrails on agent tool access | Writes policies; reviews tool-change alerts |
| **IR analyst / auditor** | Know what an agent did; evidence of control | Verifies and reads the audit log |
| **Portfolio reviewer** (hiring manager, engineer) | Judge the engineering quickly | Reads the README, runs the one-command demo, browses the design docs and tests |

## Vision (12 months)

A small, well-engineered, well-documented open-source gateway that people can adopt in minutes. Each protection is demonstrated by an attack test anyone can run, and the design docs and decision records show how it was built.

## Goals

- **G1 Drop-in.** Adopting it is a one-line change to the agent's MCP configuration.
- **G2 Tool integrity.** Detect tool poisoning and any definition change after approval.
- **G3 Least privilege.** Allow or deny each tool call by policy-as-code, including argument constraints.
- **G4 Accountability.** A tamper-evident audit record of every decision.
- **G5 Proven by tests.** Every protection has an attack scenario in the suite. CI shows each attack succeeding without Bulwark and blocked with it.
- **G6 Easy to evaluate.** A one-command demo, a clear README, and a release a reviewer can try in under 10 minutes.

## Non-goals

- **NG1** Does not solve prompt injection. Bulwark limits what a hijacked agent can do.
- **NG2** Does not measure how often AI models fall for attacks. That's covered by published research (MCPTox, MCP-SafetyBench). An optional live-model mode may come later.
- **NG3** Not a general LLM content filter, DLP product, or MCP server registry.
- **NG4** No paid services, and nothing the maintainer must run or validate by hand.
- **NG5** Does not defend against a compromised agent host or agents that bypass the gateway.

## Constraints

| Constraint | Effect on the design |
|---|---|
| **$0 budget** | Open-source dependencies only; GitHub Free plan; no paid APIs or hosted services. |
| **Maintainer time: 1–2 hours/week** | Claude designs, builds, and tests. The maintainer reviews one PR per week. Each PR is reviewable in ≤ 30 minutes, with a plain-language summary and a "Decisions for you" list. |
| **No manual testing** | All validation runs automatically in GitHub Actions. No local model runs or manual experiments. |

## Scope

> **Build order is attacks first** ([ADR-0001](docs/adr/0001-lab-first-roadmap.md), amended by [ADR-0002](docs/adr/0002-gateway-with-attack-suite.md)). Each attack scenario is written first as a test, then the gateway feature that blocks it is built. This is test-driven development applied to security.

### MVP (v0.1)
- **Attack suite:** six harmless lab scenarios, a scripted replay client, a local canary sink, and a CI results table (scenario × with/without Bulwark)
- **Gateway (stdio):** transparent proxy; tool fingerprinting and pinning (`learn` / `warn` / `enforce`); static analyzers; per-call policy with argument constraints; secret redaction; hash-chained audit log; CLI
- **Detection corpora:** analyzer detection rate measured on poisoned tool descriptions from MCPTox (license permitting), and false positive rate on real servers' tool definitions
- **One-command demo** and a signed release with an SBOM

### Later (v0.2+)
Streamable HTTP transport · multi-server aggregation · session taint tracking · human approval · ML injection classifier (CPU, runs in CI) · OpenTelemetry/OCSF export · optional "bring your own model" live benchmark

## Prior art and differentiation

| Category | Examples | Gap MCP Bulwark fills |
|---|---|---|
| Open-source MCP security gateways (2026) | MCPKernel, McpVanguard, OpenGate, Arbitus, mcp-bastion, taintmcp, mcpgate | Claims are rarely backed by a public, reproducible attack suite. **Bulwark proves each protection in CI.** |
| Vendor / platform gateways | Docker MCP Gateway, IBM ContextForge, Pomerium | Operations and access focus; heavier to adopt |
| Static scanners | MCP-Scan (now part of Snyk), mcpscan | Install-time only; no runtime enforcement or audit |
| LLM guardrails | Prompt-injection classifier models, NeMo Guardrails | Not MCP-aware; no per-tool authorization |
| Academic benchmarks | MCPTox (AAAI), MCP-SafetyBench | Measure models, not a deployable defense. **Bulwark reuses MCPTox's poisoned tools as detection test data.** |

> `VERIFY:` the features and licenses of each listed project before any public comparison. This list comes from a November 2026 search.

**Being honest about the field:** many gateways exist. This project stands out through **engineering quality and evidence** (a threat model of the gateway itself, decision records, an attack suite in CI, signed releases), not novelty alone.

## Success metrics

| Metric | Target | How measured |
|---|---|---|
| Attack suite | 100% of scenarios succeed without Bulwark and are blocked or detected with it in `enforce` mode | CI on every PR |
| Poisoning detection | ≥ 90% of the MCPTox poisoned-tool subset flagged | Analyzer corpus test in CI |
| False positives | ≤ 2% of benign real-server tool definitions flagged | Analyzer corpus test in CI |
| Rug-pull detection | 100% of definition changes detected | Scenario L-02 |
| Latency overhead | p95 < 5 ms per message | Benchmark test in CI |
| Time to evaluate | Clone to demo output in ≤ 10 minutes | Documented quickstart |
| Cost | $0 | No paid service in any workflow |

## What this project demonstrates

| Area | Evidence |
|---|---|
| Security depth | Attack scenarios mapped to OWASP Agentic/LLM risks and MITRE ATLAS; threat model of the gateway itself; coordinated-disclosure policy |
| AI security | Understanding of agent attack surfaces (tool poisoning, rug pulls, exfiltration); defenses that don't depend on the model behaving well |
| Software engineering | Protocol proxy, policy-as-code, test-driven security, CI/CD, signed releases with SBOM |
| Engineering leadership | Scoping in a crowded field, explicit constraints, ADRs, phased roadmap, PR-based review workflow |

## Risks

- **R1 The MCP spec changes quickly.** *Mitigation:* pin a spec revision; protocol handling behind an adapter layer.
- **R2 Crowded field.** *Mitigation:* compete on evidence and quality, keep scope small, and acknowledge prior art openly.
- **R3 Scripted attacks don't show how real models behave.** *Mitigation:* the suite tests what Bulwark controls (what reaches the model and which calls go through), and cites published research for model behavior. A live-model mode is a later option.
- **R4 Low maintainer time.** *Mitigation:* Claude drafts and builds; small PRs; decisions default to Claude's recommendation unless changed.

## Questions

| # | Question | Status |
|---|---|---|
| Q-A | Positioning | **Resolved:** gateway with a built-in attack suite ([ADR-0002](docs/adr/0002-gateway-with-attack-suite.md)) |
| Q-B | v0.1 transports | **Resolved:** stdio only; Streamable HTTP in v0.2 |
| Q-C | Reuse public benchmarks? | **Resolved:** yes, MCPTox poisoned tools as analyzer test data (license permitting) |
| Q-D | Budget and testing | **Resolved:** $0; all testing automated in CI |
| Q1 | Core language | Open (design 02, ADR) |
| Q2 | Policy engine (Cedar vs. OPA) | Open (design 02, ADR) |
| Q3 | Handling of sampling/elicitation | **Resolved:** passed through and audited in v0.1 |

## Maintainer notes

- Time available: 1–2 hours/week. Work arrives as PRs to review.
- Constraints: keep everything free; no manual testing or model runs.
- Purpose: a portfolio-quality project for potential employers.
