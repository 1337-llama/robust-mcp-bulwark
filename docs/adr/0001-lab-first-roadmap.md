# ADR-0001: Lab-first roadmap

| Field | Value |
|---|---|
| Status | Accepted; amended by [ADR-0002](0002-gateway-with-attack-suite.md) |
| Date | 2026-11-26 |
| Design sections | DESIGN.md §10.3, §12, §15 |
| Requirements affected | Originally FR-017, FR-018 and goal G7 (IDs from DESIGN.md v0.2). After the v0.5 renumbering: FR-001…FR-008, goal G5 |

## Context
The original roadmap built the gateway first (proxy → pinning → policy) and the attack lab and benchmark last (M4). That ordering has three problems:

- The defenses would be designed against *hypothetical* attacks, not ones shown to work against real agents.
- Nothing measurable or publishable would exist until late in the project.
- It doesn't play to the maintainer's main strength, which is offensive security.

## Options considered
| Option | Pros | Cons | Fit with goals |
|---|---|---|---|
| A. Defenses first, lab last (original) | Gateway code starts immediately | No baseline; defenses tuned to theory; late first result | Weak on G7 |
| **B. Lab first** | Baseline attack success rate (ASR) before any defense; early public write-up; every milestone measured against the same benchmark | Gateway code starts later; needs an agent runner and LLM API budget early | Strong on G7, and it shapes G2–G4 |
| C. Interleaved (each defense milestone builds its own scenarios) | Steady progress on both | No unified baseline; scenarios biased toward what's already defended | Medium |

## Decision
We will adopt **Option B**. M1 delivers the attack lab (scenarios L-01…L-06), a benchmark harness that can run agents both `direct` and through the gateway, a baseline report for at least 2 agents (client + model), and public write-up #1. Gateway work starts at M2.

## Consequences
- **Easier:** objective before/after measurement for every milestone; design decisions (analyzers, policies) grounded in observed attacks; early visible output.
- **Harder:** the benchmark harness has to be designed carefully from day one, including reproducibility, multiple runs per scenario, and benign task success alongside ASR. LLM API costs start at M1.
- **Safety:** lab servers must meet strict harmlessness constraints (canary secrets, local sink, no external network). Spec 001 encodes these as acceptance criteria.
- **Disclosure:** if baseline runs reveal a real vulnerability in a specific product, follow coordinated disclosure before write-up #1 mentions it (SECURITY.md).
- **Revisit if:** the harness turns out to be impractical without a working proxy. In that case, bring the M2 passthrough proxy forward into M1.

## Amendment (2026-11-26, ADR-0002)
The maintainer has no capacity to run or validate live-model experiments, and the project's purpose is a software portfolio. "Lab first" therefore now means **attack tests are written before the features that block them**, using a deterministic scripted replay client instead of live AI agents. There is no LLM cost and no baseline measurement of models; the design cites published research for that. The M1 write-up is dropped in favor of one launch write-up at v0.1. M1 now also includes the transparent proxy and audit log, so the suite runs through Bulwark from the start.
