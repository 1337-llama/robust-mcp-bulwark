# Specs

Each spec is one vertical slice of v0.1, traced to requirements in [DESIGN.md](../DESIGN.md) §2 and listed in the §15 backlog. Each spec folder holds `spec.md` (what and why: EARS acceptance criteria), `plan.md` (how), and `tasks.md` (ordered, test-first steps).

**Review process:** a spec's three files are reviewed together in one PR by an independent reviewer session. Claude merges the PR, under the maintainer's standing instruction, once no blockers remain ([WORKFLOW.md](../docs/WORKFLOW.md), Stage 2). Merging sets the spec to `Ready`. Implementation starts only from a `Ready` spec, and the spec becomes `Done` when its last task is merged.

| Spec | Title | Milestone | Status |
|---|---|---|---|
| [001](001-attack-suite/spec.md) | Attack suite: lab servers, replay client, runner, CI | M1 | Ready |
| [002](002-stdio-proxy/spec.md) | stdio proxy, strict JSON-RPC, revision handling, audit log, terminal-safe output | M1 | Ready |
| [003](003-pinning/spec.md) | Fingerprinting, pin store, modes, verify-before-call, server metadata | M2 | Ready |
| [004](004-analyzers/spec.md) | Static analyzers on all channels + detection corpora | M2 | Ready |
| [005](005-tools-cli/spec.md) | `tools` CLI: list, diff, approve, reject | M2 | Ready |
| [006](006-policy/spec.md) | Policy engine, argument roles, MRTR checks, `policy test` | M3 | Ready |
| [007](007-secrets/spec.md) | Secret detection and redaction | M3 | Ready on merge |
| 008 | One-command demo and release pipeline | M3 | Planned |
