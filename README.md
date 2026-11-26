# MCP Bulwark

> A security gateway between AI agents and their MCP tools. It pins and inspects tool definitions, enforces least-privilege policy on every tool call, contains data exfiltration with session taint tracking, and keeps a tamper-evident audit trail.

**Status: 🚧 Design phase. No code yet.** This project follows a spec-driven process ([docs/WORKFLOW.md](docs/WORKFLOW.md)): idea → design → specs → build. The design documents are written in the open as part of the project.

## The problem

AI agents get real capabilities (files, shells, email, cloud APIs) through the **Model Context Protocol (MCP)**. That opens new attack paths:

```
 Agent ──► [ poisoned tool description ] ──► model follows hidden instructions
 Agent ──► [ tool changes after approval ] ──► "rug pull": trusted tool turns malicious
 Agent ──► [ web page with injection ]   ──► agent reads private data ──► sends it out
```

Most current defenses are install-time scanners or chat-content filters. Neither enforces policy on each tool call at runtime.

## What MCP Bulwark does

| Capability | How |
|---|---|
| **Pin and diff** | Records a fingerprint of every approved tool definition. Any change quarantines the tool and shows a readable diff. |
| **Inspect** | Layered detectors flag hidden instructions, invisible Unicode, cross-tool manipulation, and suspicious schemas. |
| **Decide** | Policy-as-code decides allow / deny / ask for each call: who is calling, which tool, with which arguments. |
| **Contain** | Once a session has touched both private data and untrusted content, tools that can send data out are locked down. |
| **Record** | Hash-chained, SIEM-friendly audit log of every decision and its reasons. |

It deploys as a drop-in proxy: point the agent at MCP Bulwark instead of at the server.

## Roadmap: attacks first, then defenses

| Milestone | Deliverable |
|---|---|
| **M1** | **Attack lab**: deliberately malicious (harmless) MCP servers, plus a benchmark measuring how often attacks succeed against unprotected agents. Results published as write-up #1. |
| M2 | Transparent proxy (stdio + Streamable HTTP) with audit log |
| M3 | Tool pinning, static analyzers, CLI |
| M4 | Policy engine, argument constraints, secret redaction. **v0.1**, with write-up #2: attack success before vs. after |
| M5 | Session taint tracking, human approval |
| M6 | ML injection classifier, OpenTelemetry/OCSF export. **v0.2** |

Why attacks first? See [ADR-0001](docs/adr/0001-lab-first-roadmap.md).

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
