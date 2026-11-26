# ADR-0002: Evaluation-first positioning (Bench + Gateway)

| Field | Value |
|---|---|
| Status | Proposed (accepted on merge of the design PR) |
| Date | 2026-11-26 |
| Design sections | DESIGN.md §1, §2, §10, §12 |
| Requirements affected | FR-001…FR-011 (new), FR-020…FR-027; goals G1–G6 |

## Context
A prior-art search in November 2026 found at least six open-source MCP security gateways claiming features similar to ours: pinning, poisoning detection, policy enforcement, and in some cases taint tracking (MCPKernel, McpVanguard, OpenGate, Arbitus, mcp-bastion, taintmcp, mcpgate), plus vendor gateways (Docker, IBM ContextForge, Pomerium). Their effectiveness claims are self-reported.

Academic benchmarks exist (MCPTox, AAAI; MCP-SafetyBench), but they measure how vulnerable **models** are, not how much a **defense** helps, and they don't measure the defense's cost to legitimate work.

A gateway-first project would read to an expert reviewer as "yet another MCP gateway".

## Options considered
| Option | Pros | Cons | Fit with goals |
|---|---|---|---|
| A. Gateway-first (original) | Simple story; direct product | Crowded field; differentiation rests on features others already claim | Weak |
| **B. Evaluation-first: Bench (measures any defense) + Gateway (reference defense)** | Fills a real, unfilled gap; the crowded field becomes something to measure; plays to offensive strengths; builds directly on ADR-0001 (lab-first) | Two components to build; comparing others' tools needs care (fairness, disclosure) | Strong |
| C. Benchmark only, no gateway | Smallest scope | Loses the defensive engineering half of the portfolio; nothing to show "I can build the fix" | Medium |
| D. Narrow niche gateway (for example enterprise identity propagation) | Could differentiate | Needs enterprise infrastructure we can't run at $0; still unproven claims | Weak |

## Decision
We will adopt **Option B**. MCP Bulwark consists of **Bulwark Bench**, a defense-agnostic attack lab and harness that measures attack success *and* benign task success with confidence intervals, and **Bulwark Gateway**, the reference defense, evaluated by Bench like any other defense.

## Consequences
- **Easier:** clear differentiation; every claim about the gateway is backed by Bench numbers; early publishable results (M1).
- **Harder:** benchmark methodology must be rigorous: repeated runs, confidence intervals, separate run outcomes so a model that does nothing isn't counted as "secure", and versioned manifests.
- **Third-party evaluations (v0.2+)** follow IDEA.md NG2: published methodology, maintainers contacted before publication, and coordinated disclosure of any bypass (SECURITY.md).
- **$0 constraint:** Bench targets local open-weight models through an OpenAI-compatible interface. Pinned weights also improve reproducibility compared with hosted APIs that change silently.
- **Revisit if:** a widely adopted neutral MCP defense benchmark appears. In that case, contribute to it and keep Gateway as the focus.
