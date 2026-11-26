# ADR-0002: Gateway with a deterministic attack suite

| Field | Value |
|---|---|
| Status | Proposed (accepted on merge of the design PR) |
| Date | 2026-11-26 |
| Design sections | DESIGN.md §1, §2, §10, §12 |
| Requirements affected | FR-001…FR-008, FR-020…FR-027; goals G1–G6 |
| Amends | [ADR-0001](0001-lab-first-roadmap.md) |

## Context
A prior-art search in November 2026 found at least six open-source MCP security gateways with claims similar to ours (MCPKernel, McpVanguard, OpenGate, Arbitus, mcp-bastion, taintmcp, mcpgate), plus vendor gateways. Their claims are mostly self-reported. Academic benchmarks (MCPTox, MCP-SafetyBench) measure how often *models* fall for attacks.

The project's constraints:
- $0 budget
- 1–2 hours/week of maintainer time, with no capacity for running or validating experiments
- the main purpose is a portfolio that shows potential employers shipped, well-engineered security software

## Options considered
| Option | Pros | Cons | Fit with constraints |
|---|---|---|---|
| A. Gateway only | Simple; a direct product | Claims unproven, like the competitors' | Good, but weak differentiation |
| B. Evaluation-first: live-model benchmark + gateway | Fills a research gap | Needs running models, repeated experiments, and validating results, which the maintainer can't do. A research artifact is less legible to recruiters than shipped software | **Poor** |
| **C. Gateway + deterministic attack suite in CI** | Each protection proven by a test that runs automatically; no models needed; differentiates on evidence; recruiters can run the demo | Doesn't measure model behavior (cite research instead) | **Strong** |
| D. Benchmark only | Smallest | No defensive software to show | Poor |

## Decision
We will adopt **Option C**. MCP Bulwark is a **gateway** with a built-in **attack suite**:
- harmless malicious MCP servers in `lab/`
- a **scripted replay client** that sends the exact MCP messages a hijacked agent would send
- assertions that each attack **succeeds without Bulwark and is blocked or detected with it**

The suite runs in GitHub Actions on every PR. Tool-poisoning descriptions from MCPTox (license permitting) serve as analyzer test data. No AI model is required to build, test, or demo v0.1.

## Consequences
- **Easier:** no manual testing; fully deterministic CI; a one-command demo for reviewers; every README claim links to a test.
- **Harder:** the replay client must reproduce agent behavior at the protocol level faithfully, so scenarios are written from published attack descriptions.
- **Not covered:** how often real models fall for each attack. The design cites published research for this. An optional "bring your own model" live mode stays on the later roadmap.
- **ADR-0001 amended:** "lab-first" now means attack tests are written before the features that block them (test-driven security). It no longer means measuring live agents. The M1 public write-up is dropped; one launch write-up comes with v0.1.
- **Revisit if:** the maintainer gains time or budget for live-model evaluation.
