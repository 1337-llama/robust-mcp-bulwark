# Agent Firewall

> A security gateway between AI agents and their MCP tools. It pins and inspects tool definitions, enforces least-privilege policy on every tool call, contains data exfiltration with session taint tracking, and keeps a tamper-evident audit trail.

**Theme:** Securing AI · **Stage:** 0: Idea

## Documents
| Doc | Status | What it is |
|---|---|---|
| [IDEA.md](IDEA.md) | Draft | Problem, goals, scope, success metrics. **Start here and edit freely.** |
| [DESIGN.md](DESIGN.md) | Seeded skeleton | Architecture, flows, threat model, and spec backlog, to be finished section by section with Claude |
| [CLAUDE.md](CLAUDE.md) | Active | Project context and guardrails for Claude |

## The problem in one picture

```
 Agent ──► [ poisoned tool description ] ──► model follows hidden instructions
 Agent ──► [ web page with injection ]  ──► agent reads private data ──► emails it out
```

Agent Firewall sits on every one of those arrows.

## Next steps
1. Edit `IDEA.md`: sharpen scope, add maintainer notes, resolve or annotate the open questions.
2. Ask Claude to stress-test the idea (prompt in [docs/WORKFLOW.md](../docs/WORKFLOW.md#stage-0-idea)).
3. Start the design at §1–§2 (Requirements).
4. Early ADRs to write: **core language** and **policy engine**.
