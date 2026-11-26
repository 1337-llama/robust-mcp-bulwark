# MCP Bulwark

> An open, reproducible benchmark and reference defense for AI agent tool security. **Bulwark Bench** measures how often AI agents are hijacked through their MCP tools, and how much a defense actually helps. **Bulwark Gateway** is a drop-in security proxy that pins and inspects tool definitions, enforces least-privilege policy on every tool call, and keeps a tamper-evident audit trail. It runs entirely on free, open-source software and local models.

**Status: 🚧 Design phase. No code yet.** This project follows a spec-driven process ([docs/WORKFLOW.md](docs/WORKFLOW.md)): idea → design → specs → build. The design documents are written in the open as part of the project.

## The problem

AI agents get real capabilities (files, shells, email, cloud APIs) through the **Model Context Protocol (MCP)**. That opens new attack paths:

```
 Agent ──► [ poisoned tool description ] ──► model follows hidden instructions
 Agent ──► [ tool changes after approval ] ──► "rug pull": trusted tool turns malicious
 Agent ──► [ web page with injection ]   ──► agent reads private data ──► sends it out
```

Defenses are multiplying, with many open-source MCP gateways appearing in 2026. But their effectiveness claims are self-reported, and academic benchmarks measure models rather than defenses.

## Bulwark Bench: measure

An attack lab of deliberately malicious (harmless) MCP servers, plus a harness that runs AI agents against it, with or without a defense in the way. It reports:
- **Attack success rate**: how often the attack worked
- **Benign task success**: how often the agent still did its real job, because a defense that blocks everything is useless

Results come with confidence intervals and full run manifests. Any MCP proxy that wraps a stdio server can be plugged in and measured.

## Bulwark Gateway: defend

The reference defense, measured by Bench like any other.

| Capability | How |
|---|---|
| **Pin and diff** | Records a fingerprint of every approved tool definition. Any change quarantines the tool and shows a readable diff. |
| **Inspect** | Layered detectors flag hidden instructions, invisible Unicode, cross-tool manipulation, and suspicious schemas. |
| **Decide** | Policy-as-code decides allow / deny / ask for each call: who is calling, which tool, with which arguments. |
| **Record** | Hash-chained, SIEM-friendly audit log of every decision and its reasons. |
| **Contain** *(v0.2)* | Once a session has touched both private data and untrusted content, tools that can send data out are locked down. |

It deploys as a drop-in wrapper: `bulwark wrap -- <server command>`.

## Roadmap: attacks first, then defenses

| Milestone | Deliverable |
|---|---|
| **M1** | **Bulwark Bench**: attack lab, harness, and imported published attack cases. Baseline measured on local models with no defense, published as write-up #1. |
| M2 | Gateway: transparent stdio proxy with audit log |
| M3 | Tool pinning, static analyzers, CLI |
| M4 | Policy engine, argument constraints, secret redaction. **v0.1**, with write-up #2: attack success and utility, before vs. after |
| M5 | Session taint tracking, human approval, remote (HTTP) servers |
| M6 | ML injection classifier, OpenTelemetry/OCSF export. **v0.2** |

Why attacks first and why a benchmark? See [ADR-0001](docs/adr/0001-lab-first-roadmap.md) and [ADR-0002](docs/adr/0002-evaluation-first-positioning.md).

## Documentation

| Doc | What it is |
|---|---|
| [IDEA.md](IDEA.md) | Problem, goals, non-goals, scope, prior art, success metrics |
| [DESIGN.md](DESIGN.md) | Design document (in progress): requirements, architecture, threat model, spec backlog |
| [docs/adr/](docs/adr/) | Architecture Decision Records |
| [docs/WORKFLOW.md](docs/WORKFLOW.md) | How this project goes from idea to code |
| [SECURITY.md](SECURITY.md) | How to report vulnerabilities |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |

## Safety

The attack lab (`lab/`, from M1) contains **intentionally malicious MCP servers for testing only**. They use fake canary secrets, "exfiltrate" only to a local sink, and make no external network calls. Don't connect them to agents that have access to real data.

## License

[Apache License 2.0](LICENSE)
