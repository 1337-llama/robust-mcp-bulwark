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
- **AC-1** (FR-001): THE suite SHALL provide eight scenario manifests, `lab/scenarios/L-01.yaml` … `L-08.yaml`. Each declares: id, title, technique mappings (OWASP Agentic, OWASP LLM 2026, MITRE ATLAS), lab server name, revisions, canaries, replay script, and one or more control runs. Each run has a `setup` (AC-27) and expectations per condition, keyed `none`, `warn` (Bulwark in `warn` mode), and `enforce` (Bulwark in `enforce` mode). The rest of this spec uses the same three names.
- **AC-2** (FR-001): WHEN a manifest is loaded, THE suite SHALL reject unknown fields, technique IDs not in `lab/scenarios/allowlist.yaml`, and control IDs outside the control vocabulary in the same file. The vocabulary is `pin:unapproved`, `pin:changed`, `analyzer:<analyzer>/<rule or *>` for the four v0.1 analyzers, `policy:<rule id>`, `secrets:<rule>`, `mrtr:unsolicited_response`, `mrtr:unmatched_retry`, and `policy:default-deny`, matching DESIGN.md §5.3–§5.7. A rejection fails the test.
- **AC-3** (FR-002): THE lab servers SHALL read only fixtures inside the run's temporary directory, and SHALL use only canary values from the manifest.
- **AC-4** (FR-002, T-L1): THE lab servers SHALL not **directly** import networking packages. A unit test SHALL fail if any package under `lab/` imports `net`, `net/http`, or `net/rpc`. The SDK may link `net/http` internally, which is why the syscall trace (AC-21) is the real check, as in NFR-014.
- **AC-5** (FR-008, T-L2): IF `bulwark-lab` starts without the environment variable `BULWARK_LAB=1`, THEN it SHALL print an error to stderr and exit with code 2 before reading stdin.
- **AC-6** (FR-008, T-L2): WHEN `bulwark-lab` starts, it SHALL print a banner beginning with `LAB ONLY` to stderr.
- **AC-7** (T-L2): THE name of every lab server and the description of every lab tool SHALL contain the marker `[LAB]`, outside the attack payload.
- **AC-8** (T-L3): THE scenarios SHALL use only publicly documented techniques. Each manifest SHALL cite at least one public reference.
- **AC-9**: THE lab servers SHALL be deterministic: no wall-clock time and no randomness. L-02 SHALL change its tool definition after a fixed call count.

**Replay client**
- **AC-10** (FR-003): WHEN a replay script runs under revision `2026-07-28`, THE replay client SHALL put `io.modelcontextprotocol/protocolVersion` = `2026-07-28` and `io.modelcontextprotocol/clientCapabilities` in the `_meta` of every request, and SHALL NOT send `initialize`.
- **AC-11** (FR-003): WHEN a replay script runs under revision `2025-11-25`, THE replay client SHALL send `initialize` with `protocolVersion` `2025-11-25`, then `notifications/initialized`, before any other request.
- **AC-12** (FR-003): THE replay client SHALL write every line sent and received, with its direction and a sequence number, to `transcript.jsonl` in the run directory.
- **AC-13** (FR-003): WHEN a step waits for a response, THE replay client SHALL match it by JSON-RPC `id`. IF no response arrives within the step timeout (default 5 s), THEN the run SHALL end with result `timeout` rather than hang. A `timeout` counts as a failure in AC-20.
- **AC-14** (FR-003): THE replay client SHALL be able to send a scripted line verbatim (`send_raw`), so later specs can test malformed and mixed-revision input (FR-028, FR-036).

**Runner and expectations**
- **AC-15** (FR-004): WHEN the condition is `none`, THE suite SHALL assert that every observable listed for `none` is true, for all eight scenarios. These expectations are **required now**.
- **AC-16** (FR-004): WHERE an expectation is marked `pending: spec-NNN`, THE suite SHALL report it as `pending` and SHALL NOT fail the build.
- **AC-17** (FR-004): WHERE a run names a control, and the condition is `warn` or `enforce` and not pending, THE suite SHALL compare the control IDs found in the run's audit log with `controls_fired`, and SHALL fail on any difference. Exact IDs and `analyzer:<name>/*` patterns are allowed. This check is unit-tested now against fixture audit logs.
- **AC-18** (FR-036, decision 29): THE suite SHALL run every scenario under `2026-07-28`, and L-01, L-02, and L-07 also under `2025-11-25`.
- **AC-19** (FR-004): THE suite SHALL start each run in a fresh temporary directory with fresh processes. Nothing SHALL be shared between runs.

**CI**
- **AC-20** (FR-005): WHEN `suite.yml` runs, THE workflow SHALL write a Markdown results table (scenario × control × condition × revision, each cell pass, fail, or pending) to the job summary, and SHALL fail the job on any failing expectation that isn't pending.
- **AC-21** (NFR-003): WHILE the suite runs on Linux CI, it SHALL run inside an empty network namespace under `strace -f -e trace=%network`. IF any `socket()` call with domain `AF_INET` or `AF_INET6` appears in the trace, from any process, THEN the job SHALL fail. Failing on socket creation is stricter than checking `connect`/`sendto`, and doesn't depend on tracking file descriptors.
- **AC-22** (NFR-008): THE Linux suite job SHALL run the suite twice and fail IF the two `results.json` files differ, ignoring the run header.
- **AC-23** (NFR-009): EVERY PR workflow job SHALL set `timeout-minutes: 10`.
- **AC-24** (NFR-010): THE suite SHALL also run on macOS for every PR, once, without the namespace and trace.
- **AC-25** (NFR-001): THE `meta` job SHALL fail IF any workflow job uses a runner label outside the allowlist of standard GitHub-hosted labels, or IF **any** action, including `actions/*`, is not pinned to a full commit SHA.
- **AC-26** (NFR-002): THE `meta` job SHALL fail IF any requirement ID traced by a spec whose status is `Done` does not appear in a Go test name or a `// Verifies: <ID>` comment in a `_test.go` file.

**Run setup and integrity of the evidence**
- **AC-27** (FR-004): WHEN a `warn` or `enforce` cell starts, THE runner SHALL:
  1. seed the pin store as the run's `setup` says, using a preliminary `learn`-mode pass (`approve: all | none | [tool names]`, `approve_metadata: true | false`)
  2. start Bulwark with a generated configuration that enables **only** the run's control: other analyzers disabled, no operator policy files except the run's own, and secret and MRTR checks in audit-only mode unless they are the control.
- **AC-28** (FR-004): IF a run's control is not a `pin:` control, and its `setup` leaves any tool the replay calls, or the server metadata, unapproved, THEN manifest validation SHALL fail. Otherwise pinning, not the named control, would block the attack.
- **AC-29** (FR-004): THE `meta` job SHALL fail IF a spec whose status is `Done` is still named in any manifest's `pending:` field, so pending tests can't be forgotten.
- **AC-30** (NFR-003, T-L1): THE suite and the lab servers SHALL run as a non-root user in CI. WHEN the environment variable `CI` is `true` AND the effective user ID is 0, THE suite SHALL fail.
- **AC-31** (FR-002): THE secret-shaped canaries SHALL match the AWS access key ID shape exactly (`AKIA` followed by 16 uppercase letters or digits, 20 characters). THE plain canaries SHALL match no secret-like pattern in the lab's pattern list (replaced by the real rule set when spec 007 lands). Both are unit-tested.

## Out of scope
- The gateway itself (spec 002 onward). In this spec, `warn` and `enforce` expectations are all `pending`. The **configuration keys** that AC-27 relies on (`analyzers.enabled`, `secrets.requests`, `mrtr.mode`) are part of DESIGN.md §6.3 and are implemented by the specs that build each control.
- Analyzers, policies, secret rules, and the detection corpora (specs 003–007).
- The demo archive and release pipeline (spec 008).

## Open questions
None. The per-scenario designs, file formats, and CI layout are in [plan.md](plan.md).
