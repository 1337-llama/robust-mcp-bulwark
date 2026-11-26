# Spec 001: Attack suite (lab servers, replay client, runner, CI)

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-001, FR-002, FR-003, FR-004, FR-005, FR-008, NFR-001, NFR-002, NFR-003, NFR-008, NFR-009, NFR-010; threats T-L1, T-L2, T-L3 |
| Milestone | M1 |
| Depends on | DESIGN.md v0.11.1 (approved) |

## Summary
This spec builds the attack half of the project before any defense exists (ADR-0001, ADR-0002). It delivers:
- eight harmless attack scenarios (L-01…L-08), run as lab MCP servers
- a scripted replay client that acts like a hijacked agent, in both supported protocol revisions
- a suite runner that proves each attack works, and records which defenses must later block it
- the CI that runs all of this on every PR, with networking switched off

When this spec is done, the README's results table exists. Every "Without Bulwark" cell is a passing test showing that the attack works. Every "With Bulwark" cell is marked **pending** until the spec that builds that defense lands. Pending entries then turn into failing-then-passing tests: test-driven development, applied to security.

## User stories
- As a **portfolio reviewer**, I want to see each attack demonstrated by an automated test, so I can trust that the threats are real, not hypothetical.
- As the **developer of later specs**, I want each defense's target behavior written down as a pending test, so that I know exactly when a defense is done.
- As a **contributor**, I want to add a scenario by writing a manifest and a small lab server, so the suite grows without touching the runner.
- As the **maintainer**, I want the lab to be provably harmless (no network, canaries only, refuses to run by accident), so publishing it carries no risk.

## Acceptance criteria (EARS)

**Scenarios and lab servers**
- **AC-1** (FR-001): THE suite SHALL provide eight scenario manifests, `lab/scenarios/L-01.yaml` … `L-08.yaml`. Each declares: id, title, technique mappings (OWASP Agentic, OWASP LLM 2026, MITRE ATLAS), lab server name, revisions, canaries, replay script, and one or more control runs with expectations per condition (`none`, `bulwark-warn`, `bulwark-enforce`).
- **AC-2** (FR-001): WHEN a manifest is loaded, THE suite SHALL reject unknown fields, unknown control kinds (allowed: `pin`, `analyzer`, `policy`, `secrets`, `mrtr`), and technique IDs not in the allowlist checked into the repository. A rejection fails the test.
- **AC-3** (FR-002): THE lab servers SHALL read only fixtures inside the run's temporary directory, and SHALL use only canary values from the manifest.
- **AC-4** (FR-002, T-L1): THE lab servers SHALL contain no networking code. A unit test SHALL fail if any package under `lab/` imports `net`, `net/http`, or `net/rpc`.
- **AC-5** (FR-008, T-L2): IF `bulwark-lab` starts without the environment variable `BULWARK_LAB=1`, THEN it SHALL print an error to stderr and exit with code 2 before reading stdin.
- **AC-6** (FR-008, T-L2): WHEN `bulwark-lab` starts, it SHALL print a banner beginning with `LAB ONLY` to stderr.
- **AC-7** (T-L2): THE name of every lab server and the description of every lab tool SHALL contain the marker `[LAB]`, outside the attack payload.
- **AC-8** (T-L3): THE scenarios SHALL use only publicly documented techniques. Each manifest SHALL cite at least one public reference.
- **AC-9**: THE lab servers SHALL be deterministic: no wall-clock time and no randomness. L-02 SHALL change its tool definition after a fixed call count.

**Replay client**
- **AC-10** (FR-003): WHEN a replay script runs under revision `2026-07-28`, THE replay client SHALL put `io.modelcontextprotocol/protocolVersion` = `2026-07-28` and `io.modelcontextprotocol/clientCapabilities` in the `_meta` of every request, and SHALL NOT send `initialize`.
- **AC-11** (FR-003): WHEN a replay script runs under revision `2025-11-25`, THE replay client SHALL send `initialize` with `protocolVersion` `2025-11-25`, then `notifications/initialized`, before any other request.
- **AC-12** (FR-003): THE replay client SHALL write every line sent and received, with its direction and a sequence number, to `transcript.jsonl` in the run directory.
- **AC-13** (FR-003): WHEN a step waits for a response, THE replay client SHALL match it by JSON-RPC `id`. IF no response arrives within the step timeout (default 5 s), THEN the run SHALL end with result `timeout` rather than hang.
- **AC-14** (FR-003): THE replay client SHALL be able to send a scripted line verbatim (`send_raw`), so later specs can test malformed and mixed-revision input (FR-028, FR-036).

**Runner and expectations**
- **AC-15** (FR-004): WHEN the condition is `none`, THE suite SHALL assert that every observable listed for `none` is true, for all eight scenarios. These expectations are **required now**.
- **AC-16** (FR-004): WHERE an expectation is marked `pending: spec-NNN`, THE suite SHALL report it as `pending` and SHALL NOT fail the build.
- **AC-17** (FR-004): WHERE a run names a control, and the condition is a `bulwark-*` condition that is not pending, THE suite SHALL compare the control IDs found in the run's audit log with `controls_fired`, and SHALL fail on any difference. Exact IDs and `analyzer:<name>/*` patterns are allowed. This check is unit-tested now against fixture audit logs.
- **AC-18** (FR-036, decision 29): THE suite SHALL run every scenario under `2026-07-28`, and L-01, L-02, and L-07 also under `2025-11-25`.
- **AC-19** (FR-004): THE suite SHALL start each run in a fresh temporary directory with fresh processes. Nothing SHALL be shared between runs.

**CI**
- **AC-20** (FR-005): WHEN `suite.yml` runs, THE workflow SHALL write a Markdown results table (scenario × control × condition × revision, each cell pass, fail, or pending) to the job summary, and SHALL fail the job on any failing expectation that isn't pending.
- **AC-21** (NFR-003): WHILE the suite runs on Linux CI, it SHALL run inside an empty network namespace under a syscall trace. IF any `connect`, `sendto`, or `bind` on an `AF_INET` or `AF_INET6` socket appears in the trace, THEN the job SHALL fail.
- **AC-22** (NFR-008): THE Linux suite job SHALL run the suite twice and fail IF the two `results.json` files differ, ignoring the run header.
- **AC-23** (NFR-009): EVERY PR workflow job SHALL set `timeout-minutes: 10`.
- **AC-24** (NFR-010): THE suite SHALL also run on macOS for every PR, once, without the namespace and trace.
- **AC-25** (NFR-001): THE `meta` job SHALL fail IF any workflow job uses a runner label outside the allowlist of standard GitHub-hosted labels, or IF any third-party action is not pinned to a full commit SHA.
- **AC-26** (NFR-002): THE `meta` job SHALL fail IF any requirement ID traced by a spec whose status is `Done` does not appear in a Go test name or a `// Verifies: <ID>` comment in a `_test.go` file.

## Out of scope
- The gateway itself (spec 002 onward). In this spec, `bulwark-warn` and `bulwark-enforce` expectations are all `pending`.
- Analyzers, policies, secret rules, and the detection corpora (specs 003–007).
- The demo archive and release pipeline (spec 008).

## Open questions
None. The per-scenario designs, file formats, and CI layout are in [plan.md](plan.md).
