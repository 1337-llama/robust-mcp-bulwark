# MCP Bulwark: Design Document

## Document control
| Field | Value |
|---|---|
| Status | Draft: §1–§4 and §7 drafted (✅); §5–§6 seed notes, revised in design 03; others seeded (🌱) or not yet written (📝) |
| Version | 0.9 |
| Last updated | 2026-11-26 |
| Idea brief | [IDEA.md](IDEA.md) |
| Reviewers | Staff security engineer, SRE, ML engineer (roles) |

### Change history
| Version | Date | Summary |
|---|---|---|
| 0.1 | 2026-11-25 | Initial skeleton with seeded architecture, flows, and threat model starters |
| 0.2 | 2026-11-26 | Lab-first roadmap: attack lab and baseline benchmark moved to M1; added FR-017/FR-018; spec backlog renumbered |
| 0.3 | 2026-11-26 | Moved to standalone repository; renamed to MCP Bulwark (CLI `bulwark`); decision 1 recorded as ADR-0001 |
| 0.4 | 2026-11-26 | (Superseded before merge) Evaluation-first draft with live-model benchmark |
| 0.5 | 2026-11-26 | Gateway with deterministic attack suite (ADR-0002, amends ADR-0001). Drafted §1–§3; renumbered FR/NFR; stdio-only v0.1; $0 and no-manual-testing constraints; updated §10, §12, §14, §15 |
| 0.6 | 2026-11-26 | Design 02: §4 architecture (v0.1 stdio, attack suite components, verify-before-call), §7 threat model (STRIDE, mitigations mapping, accepted risks); ADR-0003 Go, ADR-0004 OPA; MCP baseline 2026-07-28; FR-028…032, NFR-013…015; file-based sink |
| 0.7 | 2026-11-26 | Review fixes B1/B2: protocol handling rewritten for 2026-07-28 (no `initialize`, per-request `_meta`, `server/discover`, MRTR, `subscriptions/listen`) with 2025-11-25 compatibility; model-visible channel inventory (§4.5); whole-object tool fingerprints; FR-033…036; T-16…T-18; AR-8, AR-9; scenarios L-07, L-08 |
| 0.8 | 2026-11-26 | Review fixes S1–S10: verify-before-call re-scoped (stale-only); policies bound to server identity and declared argument roles; `ask` = deny in v0.1 (no terminal prompt); per-control attribution in the suite; FR-032 → FR-008; NFR-003/004/010/014 made automatable and non-flaky; OWASP/ATLAS mappings corrected; CI budget; specs merged 10 → 8 with a cut line (§12.1); lossless re-serialization; T-19, AR-10, AR-11; decisions 18–24 |
| 0.9 | 2026-11-26 | §1.3 `VERIFY:` items (a)–(e) resolved against the official 2026-07-28 changelog, schema, and stdio, MRTR, and `server/discover` pages (spec repository); SEP citation corrected; stdio rule "server MUST NOT write requests" and MRTR method scope added to FR-035, FR-036, and T-17; tool-change notification wording made exact |

> **How to use this document:** follow [docs/WORKFLOW.md](docs/WORKFLOW.md) Stage 1. Each section lists **Questions to resolve**. Work through them with Claude one section at a time, replace the seeded material with agreed content, and log decisions in §14.

---

## 1. Context and scope ✅ (drafted v0.5, in review)

### 1.1 Background
The **Model Context Protocol (MCP)** is a JSON-RPC 2.0 protocol. Through it, an **MCP client** (inside an agent host such as an IDE, desktop assistant, or custom agent) discovers and invokes **tools**, **resources**, and **prompts** exposed by **MCP servers**. Servers run locally over **stdio** (as a subprocess) or remotely over **Streamable HTTP**. Everything a server says about its tools reaches the model's context, which makes the client–server boundary a security boundary that is rarely enforced.

MCP Bulwark is an **MCP-aware intermediary**. It acts as a server to the client and as a client to the upstream server, so it can inspect and control every message. It ships with an **attack suite** that proves each protection ([ADR-0002](docs/adr/0002-gateway-with-attack-suite.md)):

```mermaid
flowchart LR
  subgraph Suite["Attack suite (runs in CI)"]
    RC["Replay client<br/>(scripted hijacked agent)"]
    AS["Assertions + results table"]
    K[("Observation log<br/>(file)")]
  end
  subgraph Mode["Condition"]
    D["none (direct) · bulwark (warn) · bulwark (enforce)"]
  end
  subgraph Lab["lab/ (LAB ONLY)"]
    L["Malicious-but-harmless<br/>MCP servers L-01…L-08"]
  end
  RC <-->|"MCP over stdio"| D <-->|"MCP over stdio"| L
  L -. "exfiltration attempts" .-> K
  K --> AS
  RC --> AS
```

**Why no AI model is needed:** Bulwark never relies on the model behaving well. It inspects the server-supplied content that reaches the model, to the extent listed per channel in §4.5 (some channels are only analyzed and audited in v0.1), and it controls which calls get through. A scripted client that sends exactly what a hijacked agent would send tests those controls deterministically. How often real models get hijacked is covered by published research (for example MCPTox), which the docs cite.

### 1.2 Scope

| Area | In scope for v0.1 | Deferred |
|---|---|---|
| Transport | stdio | Streamable HTTP (v0.2) |
| Servers per gateway | One upstream server per gateway process | Multi-server aggregation with namespacing (v0.2) |
| Protocol revisions | **2026-07-28** (primary) and **2025-11-25** (compatibility); others rejected in `enforce` (FR-036) | Newer revisions as they ship |
| MCP features enforced | `tools/list`, `tools/call` (including MRTR retries), server metadata from `server/discover` or `initialize` (FR-033), tool-change notifications | Pinning and blocking for prompts and resources (v0.2) |
| MCP features analyzed and audited, not blocked | Prompts and resources (list metadata and contents), MRTR input requests (FR-034) | Policy enforcement (v0.2) |
| Server-initiated requests (2025-11-25 only: sampling, elicitation, roots) | **Passed through and audited, not enforced** | Policy enforcement (v0.2+); deprecated or replaced by MRTR in 2026-07-28 |
| Testing | Deterministic replay scenarios + detection corpora, all in CI | Optional "bring your own model" live mode (later) |
| Session-level defenses | Per-call policy only | Taint tracking (v0.2) |

### 1.3 Target protocol revision
v0.1 targets MCP specification revision **2026-07-28**, the latest at the time of drafting, supported by the official Go SDK v1.7.0 (ADR-0003). It also supports **2025-11-25** for compatibility, because clients and servers in the field will speak it for some time. Bulwark is **revision-aware but not a translator**: it forwards each message in the revision the sender used and applies the same controls in both.

What changed in 2026-07-28 that matters to Bulwark. Source: the official changelog, `schema.ts`, and the stdio transport, MRTR, and `server/discover` pages for revision 2026-07-28 in the specification repository (github.com/modelcontextprotocol/modelcontextprotocol, `main`, read 2026-11-26).

| Area | 2025-11-25 | 2026-07-28 | Bulwark impact |
|---|---|---|---|
| Handshake | `initialize` / `initialized`; version negotiated once | Handshake **removed** (SEP-2575). Each request carries `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in `_meta`, and SHOULD carry `io.modelcontextprotocol/clientInfo`. A version mismatch returns `UnsupportedProtocolVersionError` (code -32022). (SEP-2567 is the separate removal of HTTP sessions.) | The revision is determined **per message**, not per connection (FR-036) |
| Server metadata | `InitializeResult`: `serverInfo`, `capabilities`, `instructions` | `server/discover` result (`DiscoverResult`): `supportedVersions`, `capabilities`, optional `instructions`, plus required `ttlMs` and `cacheScope`. Servers SHOULD put `io.modelcontextprotocol/serverInfo` in each result's `_meta`. Servers MUST implement it; clients MAY call it first or use it as a backward-compatibility probe on stdio. `instructions` appears nowhere else in the 2026-07-28 schema | Server metadata is pinned and analyzed from either source (FR-033) |
| Server-to-client requests | `sampling/createMessage`, `elicitation/create`, `roots/list` | Replaced by **Multi Round-Trip Requests (MRTR)** (SEP-2322). On stdio the server **MUST NOT** write JSON-RPC requests to stdout. Instead it returns an `InputRequiredResult` (`resultType: "input_required"`) with an `inputRequests` map (server-assigned keys; values are `ElicitRequest`, `CreateMessageRequest`, or `ListRootsRequest`) and/or an opaque `requestState`. The client retries the original request **with a new JSON-RPC `id`**, carrying `inputResponses` under the same keys and echoing `requestState` unchanged. Only `tools/call`, `prompts/get`, and `resources/read` may return `input_required`. Roots, Sampling, and Logging are deprecated (SEP-2577), with a minimum 12-month window | MRTR input requests are analyzed and audited; the retry is a new `tools/call` through the full pipeline (FR-034, FR-035) |
| Change notifications | `notifications/tools/list_changed` | Same method name (`notifications/tools/list_changed`), but delivered **only** if the client opened `subscriptions/listen` with the `toolsListChanged` filter; tagged with `io.modelcontextprotocol/subscriptionId` (the listen request's `id`) | Both forms invalidate Bulwark's cached tool view (§4.4). A client that never subscribes gets no notification, so Bulwark relies on `ttlMs` and max-age re-checks (FR-030) |
| List caching | — | `ttlMs` and `cacheScope` required on `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/read`, and `resources/templates/list` (SEP-2549) | Recorded; used by the pin re-check schedule (design 03) |
| Removed methods | `ping`, `logging/setLevel`, `notifications/roots/list_changed` | Removed. Log level is set per request with `io.modelcontextprotocol/logLevel` in `_meta`; servers MUST NOT send `notifications/message` for requests without it (SEP-2575) | Under 2026-07-28 these methods are unknown and handled like any unknown method |

**Stdio framing is unchanged in 2026-07-28:** one newline-delimited JSON-RPC message per line, no embedded newlines; nothing but valid MCP messages on stdout; stderr is free-form logging. On stdio, all messages share one channel: responses (correlated by `id`), notifications tied to an in-flight request (`notifications/progress`, `notifications/message`), and notifications for an active `subscriptions/listen` (correlated by `io.modelcontextprotocol/subscriptionId`). A dual-revision client SHOULD probe with `server/discover` first and fall back to `initialize` only on a non-modern error or a timeout. Remaining item: `VERIFY:` whether Go SDK v1.7.0 can be pinned to 2025-11-25 per connection for the compatibility tests (tracked in ADR-0003).

### 1.4 Glossary
| Term | Definition |
|---|---|
| Tool definition | The **entire tool object** as returned by `tools/list` (for example `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `icons`, `_meta`, and any field a later revision adds) |
| Server metadata | `instructions`, server info (name, title, version, and other descriptive fields), and capabilities, from `server/discover` (2026-07-28) or `initialize` (2025-11-25) |
| Fingerprint | SHA-256 over the canonicalized (RFC 8785 JCS) tool definition or server metadata. Every field counts unless named in an explicit, audited exclude list (empty by default), so unknown fields cannot slip past pinning |
| Model-visible channel | Any server-supplied content that can reach the model or the user, such as tool definitions, server instructions, prompts, resources, results, and MRTR input requests (§4.5) |
| MRTR | Multi Round-Trip Requests (2026-07-28): a server answers a call with `resultType: "input_required"`, and the client retries the call with `inputResponses` |
| Pinning | Recording an approved fingerprint and alerting on or blocking any difference |
| Rug pull | A tool definition that changes after approval |
| Tool poisoning | Instructions aimed at the model hidden in tool metadata |
| Tool shadowing | A tool whose description manipulates how the agent uses *another* tool |
| Scenario | A lab server plus a replay script and expected outcomes per condition |
| Replay client | A scripted MCP client that sends the messages a hijacked agent would send. No AI model involved |
| Condition | How the replay client reaches the lab server: `none` (direct), `bulwark-warn`, or `bulwark-enforce` |
| Canary | A fake secret planted in the lab. If it reaches the sink, data was exfiltrated |
| Sink | The **observation log**: a local file where lab servers record tool calls and "exfiltrated" canaries. No network involved (§4.2) |
| Observables | What each scenario checks: `poison_delivered` (malicious text reached the client), `forbidden_call_executed` (the upstream server ran a call it shouldn't have), `canary_exfiltrated` (a canary reached the sink) |
| Detection corpus | A set of tool definitions (poisoned or benign) used to measure analyzer detection and false-positive rates |

---

## 2. Requirements ✅ (drafted v0.5, in review)

Requirement IDs: **FR-001…FR-019 attack suite and evaluation**, **FR-020…FR-039 Gateway v0.1**, **FR-040+ later**.

### 2.1 Functional requirements

**Attack suite and evaluation**
| ID | Requirement | Priority | Source |
|---|---|---|---|
| FR-001 | The suite shall provide scenarios L-01…L-08 (§10.3) as stdio MCP servers in `lab/`. Each has a manifest declaring ID, technique, OWASP/ATLAS mapping, replay script, and expected observables per condition. | MVP | G5 |
| FR-002 | Lab servers shall use canary secrets only, record "exfiltration" only to the local observation log, and make no network connections at all. | MVP | G5 |
| FR-003 | The replay client shall execute a scenario's replay script under a given protocol revision and record every message sent and received. Steps: for 2026-07-28, optional `server/discover`, then per-request `_meta`, `tools/list`, `tools/call` with given arguments, MRTR retries with scripted `inputResponses`, and waits on `subscriptions/listen`; for 2025-11-25, `initialize`/`initialized` first and `notifications/tools/list_changed` for waits. | MVP | G5 |
| FR-004 | For each scenario, the suite shall assert the expected observables under each condition. The attack must **succeed under `none`**, proving the scenario is real; be **detected under `bulwark-warn`** (the expected finding is in the audit log); and be **blocked under `bulwark-enforce`** (no attack observable is true). The manifest names the **control(s) expected to fire** (policy or analyzer IDs), and the suite asserts from the audit log that exactly those fired. When a scenario lists several controls, it runs once per control with only that control enabled, so each control is shown to stop the attack on its own. | MVP | G5 |
| FR-005 | CI shall run the suite on every PR and publish a results table (scenario × condition) in the job summary. A failing assertion fails the build. | MVP | G5 |
| FR-006 | An analyzer corpus test shall report detection rate on poisoned tool definitions (MCPTox subset, if its license permits; `VERIFY:` license and format; otherwise a self-written corpus that follows published technique descriptions and is labeled as such) and false-positive rate on benign tool definitions from real open-source MCP servers. | MVP | G2, G5 |
| FR-007 | A one-command demo (`make demo` or a container image) shall run selected scenarios with and without Bulwark and print the results table, with no setup beyond Docker or the release binary. | MVP | G6 |
| FR-008 | The `bulwark-lab` binary shall refuse to start unless `BULWARK_LAB=1` is set, and shall print a `LAB ONLY` banner to stderr on start. | MVP | G5 (T-L2) |

**Bulwark Gateway (v0.1, stdio)**
| ID | Requirement | Priority | Source |
|---|---|---|---|
| FR-020 | Gateway shall wrap one upstream stdio server command and proxy all MCP messages between client and server transparently when no policy applies. | MVP | G1 |
| FR-021 | Gateway shall fingerprint every tool definition (the whole tool object, minus an explicit exclude list that is empty by default and recorded in the pin store) and compare it to the pin store. New or changed tools are handled by mode: `learn` (pin automatically), `warn` (forward and alert), `enforce` (hide the tool from the client until approved). | MVP | G2 |
| FR-022 | Gateway shall run static analyzers on tool definitions and record findings with severities. At minimum: hidden Unicode, model-directed instructions, cross-tool references, and side-channel schema parameters. In `enforce` mode, tools with high-severity findings are hidden until approved. | MVP | G2 |
| FR-023 | Gateway shall evaluate a policy for every `tools/call` and enforce `allow` or `deny`. In v0.1, `ask` is treated as `deny`: the error tells the agent that approval is required, and an `approval_required` audit record names the policy ID so the operator can adjust policy or approve the tool with the CLI. v0.1 shows no interactive prompts; per-call approval comes with the approval broker (FR-043). | MVP | G3 |
| FR-024 | Policies shall be able to constrain arguments: path prefixes, URL/domain allowlists, and regex patterns. Because tool names and argument meanings are chosen by the (untrusted) server, the decision input shall identify the **server** (configured server ID plus command digest) and the tool's **pin status**. Derived attributes (cleaned path, URL scheme and host) are computed only for arguments whose **role** (`fs_path`, `egress_url`, `recipient`, …) is declared in configuration; role mappings are stored with the tool's pin, and changing them is audited. | MVP | G3 |
| FR-025 | Gateway shall detect secrets (pattern based in v0.1; entropy-based detection is deferred to cut false positives and scope) in tool arguments, MRTR `inputResponses`, and results (`content`, `structuredContent`, upstream error messages, and resource contents), and redact them according to configuration. | MVP | G3 |
| FR-026 | Gateway shall write an audit record for every decision, chained with SHA-256 hashes so that any modification or deletion is detectable. | MVP | G4 |
| FR-027 | The CLI shall support: `wrap`, `tools list/diff/approve/reject`, `policy test`, and `audit verify/tail`. | MVP | G1–G4 |
| FR-028 | Gateway shall parse every message strictly: reject duplicate object keys, invalid UTF-8, `\u` escapes that encode lone UTF-16 surrogates, and messages over the size or depth limits. It shall forward the **re-serialized form it inspected**, never the original bytes. Re-serialization shall be **lossless**: numbers are kept exactly as written (never converted to floating point, so integers above 2^53 survive), and unknown fields are kept. A property test and a fuzz target check that parse → serialize → parse yields an identical message. | MVP | G2 (T-01) |
| FR-029 | Every CLI output that includes untrusted text (tool definitions, diffs, prompts, audit fields) shall neutralize control characters, ANSI escapes, and bidi controls. | MVP | G2 (T-11) |
| FR-030 | In `enforce` mode, before forwarding a `tools/call`, Gateway shall confirm the called tool's last-seen definition matches its approved pin. It shall re-fetch `tools/list` itself when its view is stale: after a tool-change notification, when the server's `ttlMs` hint has expired, or when the view is older than `pin_recheck_max_age` (default 300 s). Setting `pin_recheck_max_age: 0` re-checks before every call (opt-in). | MVP | G2 (M-2) |
| FR-031 | Gateway shall track outstanding request IDs (client-to-server always; server-to-client too under 2025-11-25), use a reserved ID namespace for its own requests (never forwarded), and drop and audit responses that match no outstanding request. | MVP | G2 (T-04) |
| FR-033 | Gateway shall fingerprint, pin, and analyze **server metadata** (`instructions`, server info, capabilities) from `server/discover` (2026-07-28) or `initialize` (2025-11-25). In `enforce` mode, unapproved or changed metadata, or metadata with high-severity findings, has `instructions` and other free-text descriptive fields removed before forwarding until approved (name and version are kept). | MVP | G2 (M-8, B2) |
| FR-034 | Gateway shall run the FR-022 analyzers on prompts (`prompts/list` metadata and `prompts/get` messages), resources (`resources/list` and template metadata), and MRTR input requests, and audit the findings. v0.1 does not block or pin these (AR-8). | MVP | G2 (M-8, M-9) |
| FR-035 | Gateway shall treat an MRTR retry (a `tools/call` carrying `inputResponses`) as a new `tools/call`: pin check, secret scan of `inputResponses`, and policy evaluation with the input responses in the decision input. The retry has a new JSON-RPC `id` (MRTR rule), so Bulwark matches it to the earlier `input_required` result by server, method, tool name, and `requestState`; `requestState` is forwarded byte-for-byte and never inspected or modified. `inputResponses` keys that the server never requested are recorded as an `mrtr.unsolicited_response` finding, which the example policies deny. | MVP | G3 (M-9, T-16) |
| FR-036 | Gateway shall determine each message's protocol revision (per request under 2026-07-28; from the negotiated version under 2025-11-25), apply the same controls under both supported revisions, and record the revision in the audit log. Messages in an unsupported or unrecognizable revision are rejected in `enforce` mode and forwarded with an audit record in `learn` and `warn` modes. Under 2026-07-28, a JSON-RPC **request** from the server on stdout, or an `input_required` result on any method other than `tools/call`, `prompts/get`, or `resources/read`, is a protocol violation: blocked in `enforce`, audited in all modes. | MVP | G2 (T-17) |

**Later (v0.2+)**
| ID | Requirement | Priority |
|---|---|---|
| FR-040 | Streamable HTTP transport | Later |
| FR-041 | Multi-server aggregation with tool namespacing | Later |
| FR-042 | Session taint tracking and taint-aware policy | Later |
| FR-043 | Out-of-band human approval broker | Later |
| FR-044 | Prompt-injection classifier tier (CPU-only, runs in CI) | Later |
| FR-045 | OpenTelemetry and OCSF audit export | Later |
| FR-046 | Optional live-model mode: run scenarios with a real agent against a user-supplied OpenAI-compatible endpoint | Later |

### 2.2 Non-functional requirements
| ID | Category | Requirement | Measure |
|---|---|---|---|
| NFR-001 | Cost | Development, CI, and demo use no paid service | Dependency and workflow review |
| NFR-002 | Automation | All verification runs in GitHub Actions. No requirement needs a manual or local test step by the maintainer. | Every NFR and FR maps to a CI job (§10) |
| NFR-003 | Lab safety | The suite passes in a container with all networking disabled except loopback. Any other connection attempt fails the run. | CI job runs the suite under `strace -f -e trace=connect` (or an equivalent syscall trace, fixed in spec 001); any `connect` to a non-loopback, non-Unix address fails the job |
| NFR-004 | Performance | Gateway pipeline adds p95 < 5 ms per message (no ML, no human approval), measured **in-process** with the upstream excluded | Go benchmark over a fixed corpus of recorded messages with a fixed iteration count; gates at 5 ms (far above the expected cost, so shared-runner noise cannot flip it). End-to-end latency, including upstream and verify-before-call round trips, is reported in the job summary but not gated |
| NFR-005 | Reliability | Gateway fails closed by default if policy evaluation errors | Fault-injection test |
| NFR-006 | Integrity | `audit verify` detects any modified, inserted, or deleted audit record | Tamper tests |
| NFR-007 | Privacy | No data leaves the host: no telemetry, no external calls by the gateway | Network test in CI |
| NFR-008 | Determinism | Suite results are identical across reruns (no flaky tests) | Each CI run executes the suite twice and compares results |
| NFR-009 | CI time | The full CI pipeline finishes in ≤ 10 minutes | CI timing |
| NFR-010 | Portability | Linux and macOS supported; Windows best-effort | Linux on every PR; macOS on merges to `main` and releases (C-4) |
| NFR-011 | Usability | A reviewer goes from clone (or release download) to demo output in ≤ 10 minutes | Documented quickstart, scripted in CI |
| NFR-012 | Supply chain | Releases are built in CI with an SBOM and signatures (Sigstore) | Release workflow |
| NFR-013 | Resource limits | Configurable maximum message size (default 4 MiB), JSON nesting depth (default 64), outstanding requests, and notification rate. Exceeding a limit produces an error and an audit record, not a crash | Fuzz and limit tests in CI |
| NFR-014 | Attack surface | v0.1 Gateway opens no network listeners and makes no network connections; policies cannot either (T-19) | Network-disabled, syscall-traced CI run (as in NFR-003); a CI check that fails if Bulwark's own packages import `net` or `net/http` directly (dependencies such as OPA may link them, which is why the trace is the real check); a test that loading a policy using `http.send` fails |
| NFR-015 | Dependency hygiene | Dependencies pinned (`go.sum`); `govulncheck` and dependency review run in CI; no known-vulnerable dependency at release | CI job |

### 2.3 Constraints and assumptions
| ID | Type | Statement |
|---|---|---|
| C-1 | Constraint | $0 budget (NFR-001). No paid APIs, hosted services, or paid GitHub features. |
| C-2 | Constraint | Maintainer time is 1–2 hours/week. Claude designs, builds, and tests; the maintainer reviews PRs (≤ 30 minutes each). |
| C-3 | Constraint | No manual testing or local model runs (NFR-002). |
| C-4 | Constraint | The repo is private until the v0.1 launch. GitHub Actions usage for private repos on the Free plan is limited (`VERIFY:` current allowance and pricing model; 2,000 Linux minutes/month at time of drafting), and **macOS runners cost about 10× Linux**. Budget: PR runs are Linux only (suite run twice for NFR-008, about 10 minutes); macOS runs on merges to `main` and on releases. At about 1 PR per week this stays well inside the allowance. Making the repo public earlier would remove this limit (maintainer's decision). |
| A-1 | Assumption | Protocol-level replay is a faithful test of Bulwark's controls, because Bulwark acts only on protocol messages. It does **not** show how often a model would follow the malicious instructions. The docs cite published research for that (R3 in IDEA.md). |
| A-2 | Assumption | The official Go MCP SDK (stable since v1.0.0; v1.7.0 supports revision 2026-07-28) is sufficient for the lab servers and replay client under both supported revisions (`VERIFY:` per-connection pinning to 2025-11-25, §1.3). The gateway parses JSON-RPC itself (ADR-0003). |

---

## 3. Users and use cases ✅ (drafted v0.5, in review)

### 3.1 Personas
See [IDEA.md](IDEA.md#target-users). The primary persona for v0.1 is the **developer using agents**. The **portfolio reviewer** is a first-class persona: the README, demo, and design docs are written for a 10-minute evaluation.

### 3.2 Use cases
| ID | Actor | Trigger | Main flow | Outcome | Traces to |
|---|---|---|---|---|---|
| UC-01 | Portfolio reviewer | Opens the repo | Reads the README, runs `make demo` (or the container) | Sees each attack succeed without Bulwark and get blocked with it, in one table | FR-007, NFR-011 |
| UC-02 | Developer | Adds a third-party stdio server | Wraps it with `bulwark wrap -- <cmd>` in `learn` mode, reviews findings, switches to `enforce` | Poisoned description flagged; tool hidden until approved | FR-020…022, FR-027 |
| UC-03 | Developer | A server silently changes a tool (rug pull) | Gateway detects a fingerprint mismatch on the next `tools/list` | Tool quarantined; `bulwark tools diff` shows the change | FR-021, FR-027 |
| UC-04 | Developer | A hijacked agent tries to send data to an unapproved domain | Policy with a domain allowlist evaluates the `tools/call` | Call denied with the policy ID; audit record written | FR-023, FR-024, FR-026 |
| UC-05 | IR analyst | Investigating an agent's actions | `bulwark audit verify`, then `audit tail` filtered by session | Integrity confirmed; session reconstructed | FR-026, FR-027 |
| UC-06 | Contributor | Wants to add an attack | Proposes a scenario through the issue template; implements it under `lab/` with a manifest | CI runs it on every PR from then on | FR-001…005 |

### 3.3 Hero demos (README and launch write-up)
1. **UC-01 "Attacks vs. Bulwark"**: one table and a terminal recording of six attacks, each succeeding directly and blocked through Bulwark.
2. **UC-03 "Rug pull caught"**: a tool changes after approval, is quarantined, and the diff is shown.

---

## 4. Architecture ✅ (drafted v0.6, in review)

v0.1 architecture: one Bulwark process per wrapped stdio server, written in Go ([ADR-0003](docs/adr/0003-implementation-language.md)), with policies in OPA/Rego ([ADR-0004](docs/adr/0004-policy-engine.md)). It opens **no network listeners** and makes **no network connections** (NFR-014).

### 4.1 System context

```mermaid
flowchart LR
  subgraph Host["Agent host (TB1)"]
    C["MCP client<br/>(IDE, desktop app, agent)"]
  end
  subgraph BW["bulwark wrap -- &lt;cmd&gt; (TB2)"]
    FE["Client side<br/>stdin / stdout"]
    PL["Message pipeline<br/>parse → intercept → re-serialize"]
    BE["Upstream side<br/>child process pipes"]
  end
  subgraph Up["Upstream MCP server (untrusted, TB3)"]
    S["child process<br/>(optionally inside a container)"]
  end
  subgraph St["Local state (TB4)"]
    CF["config.yaml"]
    PN["pins.json"]
    PO["policies/*.rego"]
    AU["audit.jsonl"]
  end
  OP(["Operator"])
  C <-->|"JSON-RPC over stdio"| FE
  FE <--> PL <--> BE
  BE <-->|"stdin/stdout<br/>(stderr passed through)"| S
  PL --- CF
  PL --- PN
  PL --- PO
  PL --> AU
  OP -->|"bulwark tools / audit / policy<br/>(separate CLI invocations)"| St
```

The MCP client launches `bulwark wrap -- <server command>` instead of the server. Bulwark starts the real server as a child process and sits on both pipes. To the client it is a server, and to the server it is a client.

### 4.2 Components

**Gateway (`bulwark`)**
| Package | Responsibility | Key requirements |
|---|---|---|
| `cmd/bulwark` | CLI entry point: `wrap`, `tools`, `policy`, `audit` | FR-027 |
| `internal/jsonrpc` | Strict framing and parsing of newline-delimited JSON-RPC: size limits, duplicate-key rejection, UTF-8 validation, canonical re-serialization | FR-028, NFR-013 |
| `internal/mcprev` | Protocol revision handling: detects each message's revision (per-request `_meta` for 2026-07-28, negotiated version for 2025-11-25), maps revision-specific shapes (handshake vs. `server/discover`, MRTR vs. server-initiated requests, change-notification forms) onto one internal model for the interceptors | FR-036 |
| `internal/proxy` | Owns both pipes and the child process lifecycle. Tracks request IDs per direction, routes messages through the pipeline, issues gateway-originated requests in a reserved ID space | FR-020, FR-030, FR-031 |
| `internal/pipeline` | Ordered interceptors keyed by (direction, method). Each returns *forward*, *modify*, or *block with error* | FR-020…025 |
| `internal/registry` | JCS canonicalization, whole-object fingerprints for tools and server metadata, pin store (JSON file), `learn`/`warn`/`enforce` modes, diffs | FR-021, FR-030, FR-033 |
| `internal/analyzers` | Analyzer interface, text normalization helpers, the first four analyzers, applied to every model-visible channel in §4.5 | FR-022, FR-033, FR-034 |
| `internal/policy` | Embedded OPA: decision-input builder (including derived attributes such as cleaned paths and URL hosts), prepared queries, decision combining | FR-023, FR-024, NFR-005 |
| `internal/redact` | Secret detectors (patterns in v0.1; entropy later) for arguments, MRTR input responses, and results | FR-025, FR-035 |
| `internal/audit` | Hash-chained JSONL writer, `verify`, `tail` | FR-026, NFR-006 |
| `internal/config` | YAML configuration with JSON Schema validation | — |
| `internal/termsafe` | Neutralizes untrusted text (control characters, ANSI escapes, bidi controls) before printing it to a terminal | FR-029 |

**Attack suite (`lab/`)**
| Package | Responsibility | Key requirements |
|---|---|---|
| `lab/cmd/bulwark-lab` | One binary containing lab servers L-01…L-08 (built on the official Go SDK). Refuses to start unless `BULWARK_LAB=1`; prints a `LAB ONLY` banner to stderr | FR-001, FR-002, FR-008 |
| `lab/scenarios/*.yaml` | Scenario manifests: technique, mappings, replay script, expected observables per condition | FR-001, FR-004 |
| `lab/replay` | Replay client: an MCP client (Go SDK) that executes a replay script under a chosen protocol revision and records the transcript | FR-003 |
| `lab/suite` | Go tests: for each scenario × condition × revision, start the stack, replay, read the observation log, assert. All scenarios run under 2026-07-28; a compatibility subset (L-01, L-02, L-07) also runs under 2025-11-25 | FR-004, FR-036, NFR-008 |
| `tools/ci-summary` | Renders suite results (JSON) as a Markdown table for the GitHub Actions job summary and the README | FR-005 |

**Sink design:** lab servers never use the network. Their "exfiltration" tools append to an **observation log** file given by `BULWARK_LAB_OBS`, which the suite reads to compute observables. This is safer than a loopback listener and lets the suite run with networking fully disabled (NFR-003).

### 4.3 Repository layout (v0.1)
```
cmd/bulwark/            CLI
internal/               gateway packages (§4.2)
lab/                    LAB ONLY: attack servers, scenarios, replay client, suite
  cmd/bulwark-lab/
  scenarios/
  replay/
  suite/
testdata/corpora/       detection corpora (MCPTox subset, benign definitions)
policies/examples/      example Rego policies + their tests
tools/ci-summary/
docs/                   ADRs, workflow, write-ups
.github/workflows/      CI: test, suite, lint, vuln scan, release
```

### 4.4 Key flows

**Server metadata (`server/discover` under 2026-07-28, `initialize` under 2025-11-25)**
```mermaid
sequenceDiagram
  participant C as Client
  participant B as Bulwark
  participant U as Upstream
  C->>B: server/discover (2026-07-28) or initialize (2025-11-25)
  B->>U: forwarded (re-serialized)
  U-->>B: supportedVersions / protocolVersion, capabilities, instructions, server info
  B->>B: record revision(s), fingerprint metadata (JCS), compare with pin
  B->>B: run analyzers on instructions and descriptive fields
  B->>B: enforce + unapproved, changed, or high finding → remove instructions and free-text fields
  B->>B: audit(metadata, findings, pin status)
  B-->>C: re-serialized, possibly reduced result
```
Under 2026-07-28 a client may never call `server/discover`. Bulwark then issues its own `server/discover` (reserved ID namespace, FR-031) on the first client request, so server metadata is always pinned and audited even if it never reaches the client. This covers every route: in the 2026-07-28 schema, `instructions` appears only in `DiscoverResult`.

**Tool discovery (`tools/list`)**
```mermaid
sequenceDiagram
  participant C as Client
  participant B as Bulwark
  participant U as Upstream
  C->>B: tools/list (id 7)
  B->>U: tools/list (id 7)
  U-->>B: result: tool definitions (+ nextCursor)
  B->>B: strict parse, canonicalize (JCS), fingerprint
  B->>B: compare with pins: new / unchanged / changed
  B->>B: run analyzers, record findings
  B->>B: apply mode: learn / warn / enforce (hide unapproved tools)
  B->>B: audit(discovery, findings, pin status)
  B-->>C: re-serialized, filtered result (id 7)
```
Paginated results (`nextCursor`) are handled page by page. A tool-change notification from upstream (`notifications/tools/list_changed` in both revisions; under 2026-07-28 it arrives only on a client-opened `subscriptions/listen` stream and carries `io.modelcontextprotocol/subscriptionId`) is forwarded to the client and invalidates the gateway's cached view, so the next `tools/list` is re-checked. `ttlMs` and `cacheScope` hints are recorded in the audit log; how they feed the re-check schedule is decided in design 03.

**Tool invocation (`tools/call`)**
```mermaid
sequenceDiagram
  participant C as Client
  participant B as Bulwark
  participant U as Upstream
  C->>B: tools/call {name, arguments} (id 9)
  opt enforce mode and pin check is stale
    B->>U: tools/list (id "bulwark-1", gateway-originated)
    U-->>B: definitions (consumed, not forwarded)
    B->>B: re-verify fingerprint of the called tool
  end
  B->>B: tool approved? (else deny)
  B->>B: secret scan on arguments → redact / finding
  B->>B: policy(tool, arguments, derived attributes, findings)
  alt deny
    B-->>C: error result with policy ID (id 9)
  else allow
    B->>U: tools/call, re-serialized, possibly redacted (id 9)
    U-->>B: result
    alt resultType "input_required" (MRTR, 2026-07-28)
      B->>B: analyze input requests (FR-034), audit
      B-->>C: input_required result (id 9)
      Note over C,B: client retries as a NEW tools/call<br/>(new id, inputResponses + requestState):<br/>full pipeline again, inputResponses<br/>secret-scanned and in the policy input (FR-035)
    else complete
      B->>B: secret scan on content, structuredContent → redact
      B-->>C: result (id 9)
    end
  end
  B->>B: audit(call, revision, decision, policy IDs, latency)
```
**MRTR retries (FR-035):** under 2026-07-28, a server asks for more input by returning `input_required` instead of sending its own request. The client's answers travel back to the server inside the retried `tools/call`, which makes them an exfiltration channel. Bulwark therefore gives the retry no shortcut: it is pin-checked, secret-scanned, and evaluated by policy like any other call, with `input.request.input_responses` and `input.request.is_retry` available to policies (§5.3). Under 2025-11-25 the same requests arrive as server-initiated `sampling/createMessage`, `elicitation/create`, or `roots/list`; v0.1 passes those through and audits them (decision 6).
**Verify before call (FR-030), and what it does and does not buy:** a changed definition can only reach the model through a `tools/list` response, and Bulwark already checks every one of those (FR-021). So the poisoning half of a rug pull is caught without any re-check. The re-check adds one thing: it notices that the server's **implementation has changed** (a new definition) even when the client never re-lists, and blocks calls to the changed tool until it is re-approved. That is a useful signal of a behavioral change, but only a signal. A malicious server defeats it by always answering `tools/list` with the pinned definition, which is exactly the behavioral rug pull in T-06 (AR-4). The re-check therefore runs when Bulwark's view is stale (after a change notification, when `ttlMs` expires, or after `pin_recheck_max_age`, default 300 s), not before every call. Re-checking before every call is opt-in, because it doubles upstream traffic and can disturb stateful servers for little extra protection.

**Attack suite run (CI)**
```mermaid
sequenceDiagram
  participant T as Suite test
  participant R as Replay client
  participant B as Bulwark (or none)
  participant L as bulwark-lab Lxx
  participant O as Observation log
  T->>T: fresh temp dir, BULWARK_LAB=1, BULWARK_LAB_OBS=path
  T->>R: start with condition (none / bulwark-warn / bulwark-enforce) and revision
  R->>B: replay script (server/discover or initialize, tools/list, tools/call, MRTR retries…)
  B->>L: (forwarded or blocked)
  L->>O: record calls and "exfiltrated" canaries
  R-->>T: transcript (messages received)
  T->>O: read observations
  T->>T: compute observables, assert expectations, emit results JSON
```

**Decided in this draft** (§14.1): one process per server (no aggregation in v0.1), file-based sink, verify-before-call by default, two supported revisions without translation, MRTR retries as full calls. **Deferred to design 03:** whether a deny is returned as a JSON-RPC error or as a tool result with `isError: true`.

### 4.5 Model-visible channels
Every place where server-supplied text can reach the model or the user, and what v0.1 does about it. This table bounds the claim in §1.1: a channel not marked **pinned** or **blocked** is a residual risk (§7.6).

| # | Channel | Revision | Reaches | v0.1 handling | Requirement | Residual |
|---|---|---|---|---|---|---|
| CH-1 | Tool definitions (whole object) | both | Model | **Pinned, analyzed, hidden** in `enforce` until approved | FR-021, FR-022, FR-030 | AR-5 |
| CH-2 | Server `instructions` and server info | both (`server/discover` or `initialize`) | Model (clients may add instructions to the model's context) | **Pinned, analyzed, stripped** in `enforce` until approved | FR-033 | AR-5 |
| CH-3 | Tool results: `content`, `structuredContent` | both | Model | Secrets redacted; injection **not** detected in v0.1 | FR-025 | AR-7, AR-9 |
| CH-4 | Prompts: `prompts/list` metadata, `prompts/get` messages | both | Model (when the user picks a prompt) | Analyzed and audited; not pinned or blocked | FR-034 | AR-8 |
| CH-5 | Resources: list and template metadata, `resources/read` contents | both | Model | Metadata analyzed; contents secret-scanned; audited | FR-025, FR-034 | AR-8, AR-9 |
| CH-6 | MRTR input requests (elicitation text, sampling prompts) | 2026-07-28 | User and model | Analyzed and audited; the answers are policy-checked on retry | FR-034, FR-035 | AR-8 |
| CH-7 | Server-initiated sampling, elicitation, roots | 2025-11-25 | User and model | Passed through and audited | FR-026 | T-05 |
| CH-8 | Upstream error messages and `data` | both | Model (often shown as tool output) | Secret-scanned and audited | FR-025 | AR-9 |
| CH-9 | Logging and progress notifications | both (logging deprecated in 2026-07-28) | Usually user only (`VERIFY:` per client) | Rate-limited and audited | NFR-013 | AR-9 |

## 5. Detailed design 📝 (seed notes; revised in design 03)

> Seed notes below predate design 02. Where they conflict with §4 (for example multi-server aggregation or session taint in v0.1), §4 wins.

### 5.1 Tool registry and pinning
- Canonicalization: RFC 8785 JCS over `{server_id, tool}`, where `tool` is the **whole tool object** as received (decided in v0.7, decision 15). Annotations, `icons`, `_meta`, and fields added by later revisions all count. Fields can be excluded only through an explicit exclude list, which is empty by default, stored in the pin store, and audited when changed. Server metadata (FR-033) is fingerprinted the same way.
- Pin store records: `server_id, tool_name, fingerprint, definition_snapshot, approved_by (role), approved_at, findings_at_approval`.
- Diffs are shown as a unified text diff of descriptions plus a structural JSON diff of schemas.
- A tool-change notification (`notifications/tools/list_changed` under 2025-11-25, or via `subscriptions/listen` under 2026-07-28) triggers re-discovery and re-evaluation of pins.
- **Server identity:** how is "the same server" established across runs? For stdio, a command + args + package version/hash. For HTTP, URL + TLS identity. `VERIFY:` whether the current MCP spec offers server identity metadata.

### 5.2 Static analyzers (definition inspection)
| Analyzer | Detects | Notes |
|---|---|---|
| `unicode.hidden` | Zero-width characters, bidi controls, Unicode Tags block (U+E0000–U+E007F), homoglyphs in names | High precision |
| `text.imperative` | Instructions aimed at the model ("ignore previous", "do not tell the user", `<IMPORTANT>` blocks) | Heuristic; tune against a benign corpus |
| `text.cross_reference` | Mentions of other tools or servers (shadowing) | Compare against the registry |
| `text.sensitive_ref` | References to `~/.ssh`, `.env`, credentials, tokens | |
| `schema.side_channel` | Free-text params that solicit context (`notes`, `context`, `metadata`) unrelated to the stated purpose | Exfiltration through arguments |
| `annotation.mismatch` | `readOnlyHint: true` on a tool whose name or description implies writes or egress | Annotations are **untrusted hints** per the MCP spec |
| `size.anomaly` | Unusually long descriptions | |

### 5.3 Policy engine
OPA/Rego, embedded ([ADR-0004](docs/adr/0004-policy-engine.md)). Decision input (v0.1 draft):

```json
{
  "server": {"id": "web", "command_digest": "sha256:…"},
  "tool": {"name": "http_post", "pin_status": "approved", "arg_roles": {"url": "egress_url"}, "annotations": {"readOnlyHint": false}},
  "arguments": {"url": "https://api.example.com/v1/upload", "body": "…"},
  "request": {"revision": "2026-07-28", "is_retry": false, "input_responses": null},
  "derived": {"egress_url": {"scheme": "https", "host": "api.example.com"}, "fs_path": null, "args_bytes": 812},
  "findings": [{"analyzer": "secrets", "severity": "high", "location": "arguments.body"}],
  "mode": "enforce"
}
```

`server.id` is the name the operator gave the wrapped server in configuration, and `command_digest` identifies what was launched. Both come from Bulwark, not from the server. `tool.arg_roles` comes from configuration and is pinned with the tool. A tool with no declared roles gets no derived attributes, so a rule that needs one simply does not match, and default-deny applies.

Example policy. The gateway combines the sets: any `deny` → deny; else any `ask` → ask (in v0.1, deny with an `approval_required` record); else any `allow` → allow; else deny.

```rego
package bulwark.authz

# Rego v1 syntax (the default in OPA 1.x, so no `import rego.v1` is needed).

# Reads only inside the workspace, and only from the server configured as "fs".
# fs_path is the cleaned path the gateway derived from the argument declared as fs_path.
allow contains "fs-read-workspace" if {
	input.server.id == "fs"
	input.tool.pin_status == "approved"
	input.tool.name == "read_file"
	startswith(input.derived.fs_path, "/workspace/")
}

# Outbound HTTP only from the "web" server, only to approved hosts.
allow contains "http-allowlist" if {
	input.server.id == "web"
	input.tool.pin_status == "approved"
	input.tool.name == "http_post"
	input.derived.egress_url.host in {"api.example.com"}
}

# Never send anything that looks like a secret.
deny contains "no-secrets-out" if {
	some f in input.findings
	f.analyzer == "secrets"
	startswith(f.location, "arguments")
}
```

### 5.4 Taint tracker (v0.2)
- Labels are **session-level and only ever added** (they are never removed within a session). This is coarse but sound and easy to reason about.
- Sources of labels: tool classification in config (for example `email.read` → `sensitive_data`, `web.fetch` → `untrusted_content`), server trust level, and analyzer findings on results.
- Capability tags on tools: `read`, `write`, `exec`, `egress`, `read_external`.
- Inspired by information-flow defenses such as CaMeL (Google DeepMind, 2025). Clearly document what this simplified model does *not* catch, such as egress through a write tool that syncs to the cloud.

### 5.5 Inspection of results
Secret detection (regex rules similar in spirit to gitleaks in v0.1; entropy scoring later) and the injection classifier score (§8). Possible actions: annotate, redact, block, or add a taint label.

### 5.6 Approval broker (v0.2)
Channels: interactive CLI, webhook (Slack/Teams), and possibly MCP elicitation back to the client. `VERIFY:` whether elicitation is suitable, since it shows the request through the very client that might be compromised. Timeout leads to the policy-defined default (deny).

### 5.7 Audit logger
See §6.3 for the record schema. Hash chain: `hash = SHA-256(prev_hash || canonical(record))`. Periodic checkpoints can be signed or anchored externally (v0.2).

**Questions to resolve**
1. ~~Do annotations count toward fingerprints?~~ Resolved in v0.7: the whole tool object counts (decision 15).
2. How is server identity defined for stdio and HTTP?
3. Tag tools with capabilities manually, by heuristics, or both (heuristics suggest, humans confirm)?
4. Should argument redaction ever be silent, or should the agent always be told that redaction happened?

---

## 6. Interfaces and data model 🌱 (revised in design 03)

> The configuration example below predates design 02. v0.1 configures **one upstream per `bulwark wrap` invocation**; the multi-server form is for v0.2.

### 6.1 CLI (draft)
```
bulwark run --config gateway.yaml           # (v0.2) start a multi-server gateway
bulwark wrap -- npx -y <server-package>    # quick local stdio wrapper
bulwark tools list|diff|approve|reject
bulwark policy test --input call.json      # dry-run a decision
bulwark audit verify|tail                  # export --format ocsf in v0.3
bulwark lab run <scenario>                 # (later) lab is driven by `go test` in v0.1
```

### 6.2 Configuration schema (draft)
```yaml
servers:
  filesystem:
    transport: stdio
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
    trust: internal
    tools:
      read_file:  { capabilities: [read],  labels_on_result: [sensitive_data] }
      write_file: { capabilities: [write] }
  web:
    transport: http
    url: https://mcp.example.com/mcp
    trust: external
    auth: { type: oauth2, client_id_env: WEB_MCP_CLIENT_ID }
    default_labels_on_result: [untrusted_content]
pinning:
  mode: enforce            # learn | warn | enforce
  store: ./state/pins.db
policy:
  engine: opa              # ADR-0004
  path: ./policies/
  on_engine_error: deny    # fail-closed
inspection:
  secrets: { enabled: true, action: redact }
  injection_classifier: { enabled: false }
audit:
  sink: file
  path: ./logs/audit.jsonl
  hash_chain: true
```

### 6.3 Audit record (draft)
```json
{
  "ts": "2026-11-25T14:03:22.118Z",
  "seq": 1042,
  "session_id": "s_7f3a",
  "principal": "agent:code-assistant",
  "event": "tool_call",
  "server": "web",
  "tool": "fetch",
  "args_digest": "sha256:…",
  "args_redacted": {"url": "https://example.com/page"},
  "decision": "deny",
  "policy_ids": ["trifecta-egress"],
  "findings": [],
  "taint_before": ["sensitive_data", "untrusted_content"],
  "taint_after":  ["sensitive_data", "untrusted_content"],
  "latency_ms": {"gateway": 1.8, "upstream": null},
  "prev_hash": "sha256:…",
  "hash": "sha256:…"
}
```
`VERIFY:` mapping to OCSF. API Activity (class 6003) is the likely fit; confirm the class and required fields against the current OCSF schema.

**Questions to resolve**
1. Should the config format be YAML with a JSON Schema for validation? (Recommended.)
2. Which arguments are logged in full, digested, or redacted by default?

---

## 7. Security and threat model ✅ (drafted v0.6, in review)

Scope: v0.1 (stdio, one upstream per process, no network). Method: data-flow diagram + STRIDE per trust boundary, plus attacker-driven abuse cases. Threats Bulwark **mitigates** (§7.3), threats **to** Bulwark (§7.4–7.5), and **accepted risks** (§7.6) are kept separate.

### 7.1 Assets
| ID | Asset | Why it matters |
|---|---|---|
| A-1 | Data reachable through tools (files, mail, tokens) | The thing attackers want to exfiltrate |
| A-2 | Integrity of what reaches the model (tool definitions, results) | Poisoned context hijacks the agent |
| A-3 | Policy, pin store, and configuration | Tampering silently disables protection |
| A-4 | Audit log | Evidence for investigation; must be trustworthy |
| A-5 | Operator's attention and terminal | Misleading prompts and diffs trick approvals |
| A-6 | Availability of the agent's tools | A gateway that breaks work gets removed |

### 7.2 Trust boundaries

```mermaid
flowchart LR
  C["MCP client<br/>(trusted to follow protocol,<br/>model may be hijacked)"] -- "TB1: stdio pipes" --> B["Bulwark"]
  B -- "TB3: stdio pipes" --> U["Upstream server<br/>(UNTRUSTED code + content)"]
  B -- "TB4: filesystem" --> S[("config, pins,<br/>policies, audit")]
  O(["Operator"]) -- "TB5: CLI" --> B
  U -. "same OS user unless containerized" .-> S
```
| Boundary | Between | Trust assumption |
|---|---|---|
| TB1 | Client ↔ Bulwark | Client process is trusted. **The model driving it may be hijacked**, so its requests are untrusted. |
| TB2 | Inside Bulwark | Trusted code; our own attack surface (parser, pipeline) |
| TB3 | Bulwark ↔ upstream | **Untrusted**: definitions, results, notifications, and server-initiated requests may all be malicious |
| TB4 | Bulwark ↔ local state | Trusted only if the upstream can't write to it (see AR-2) |
| TB5 | Operator ↔ Bulwark | Operator is trusted. Text shown to them comes from untrusted sources |

### 7.3 Threats Bulwark mitigates
| ID | Threat | OWASP Agentic Top 10 (Dec 2025) | OWASP LLM Top 10 (2026) | MITRE ATLAS | v0.1 control | Scenario |
|---|---|---|---|---|---|---|
| M-1 | Tool poisoning in definitions | ASI01 Agent Goal Hijack; ASI04 Agentic Supply Chain Vulnerabilities | LLM01 Prompt Injection | AML.T0051.001 LLM Prompt Injection: Indirect | Analyzers + hide in `enforce` (FR-022) | L-01, L-06 |
| M-2 | Rug pull (definition changes after approval) | ASI04 Agentic Supply Chain Vulnerabilities | LLM01 | AML.T0010 AI Supply Chain Compromise (`VERIFY:`) | Pinning + verify-before-call (FR-021, FR-030) | L-02 |
| M-3 | Tool shadowing (one tool's text steers another's use) | ASI02 Tool Misuse and Exploitation | LLM01 | AML.T0051.001 | Cross-reference analyzer + argument policy (FR-022, FR-024) | L-03 |
| M-4 | Indirect injection through tool results, leading to exfiltration | ASI01 Agent Goal Hijack | LLM01; LLM02 Sensitive Information Disclosure | AML.T0051.001 | Egress allowlist + secret redaction (FR-024, FR-025) | L-04 |
| M-5 | Data exfiltration through tool arguments | ASI02 Tool Misuse and Exploitation | LLM02 | AML.T0086 Exfiltration via AI Agent Tool Invocation (`VERIFY:`) | Schema analyzer + argument redaction (FR-022, FR-025) | L-05 |
| M-6 | Over-privileged tool use | ASI03 Identity and Privilege Abuse | LLM03 Excessive Agency (2026 numbering; `VERIFY:` on genai.owasp.org) | — | Default-deny policy with argument constraints (FR-023, FR-024) | Policy tests |
| M-7 | No record of agent actions | — (supports detection and response for every ASI risk; it mitigates none directly) | — | — | Hash-chained audit (FR-026) | Tamper tests |
| M-8 | Poisoning through server metadata (`instructions`, server info) and other non-tool channels (prompts, resources) | ASI01 Agent Goal Hijack; ASI04 Agentic Supply Chain Vulnerabilities | LLM01 | AML.T0051.001 | Pin, analyze, and strip server metadata in `enforce` (FR-033); analyze and audit prompts and resources (FR-034) | L-07 |
| M-9 | Solicitation and exfiltration through MRTR input requests (the server asks for data; the answer goes back to it) | ASI01 Agent Goal Hijack; ASI09 Human-Agent Trust Exploitation (`VERIFY:` title) | LLM01; LLM02 | AML.T0051.001 | Retry evaluated as a full call: secret scan of `inputResponses` + policy (FR-035); input requests analyzed (FR-034) | L-08 |

> OWASP Agentic IDs and titles were confirmed against several secondary sources in November 2026. Tool poisoning is mapped to the **indirect** prompt-injection sub-technique (AML.T0051.001), because tool metadata is content the model ingests. Before v0.1, `VERIFY:` against the primary sources: the ASI09 title (genai.owasp.org), LLM03 in the 2026 LLM list (several entries moved from 2025), and AML.T0010 and AML.T0086 (atlas.mitre.org).

### 7.4 Threats to Bulwark (STRIDE)
| ID | Boundary | STRIDE | Threat | Mitigation | Requirement | Residual |
|---|---|---|---|---|---|---|
| T-01 | TB3 | Tampering | **Parser differential:** a message with duplicate JSON keys (`"description"` twice) is read one way by Bulwark and another way by the client, so the analyzers inspect harmless text while the model sees the poison | Reject duplicate keys and invalid UTF-8; **forward the re-serialized form Bulwark inspected**, never the original bytes | FR-028 | Low |
| T-02 | TB3 | Tampering | Unicode tricks (homoglyphs, zero-width characters, Tag-block characters, bidi controls) hide instructions from pattern matching | Analyzers inspect both raw and NFKC-normalized text; `unicode.hidden` flags invisible characters | FR-022 | Medium (new encodings) |
| T-03 | TB3 | DoS | Oversized, deeply nested, or flooding messages (including notification storms) exhaust memory or CPU | Size and depth limits, bounded queues, rate limits on notifications; violations error out and are audited | NFR-013 | Low |
| T-04 | TB3 | Spoofing | **Response ID confusion:** upstream answers with the ID of another outstanding request, or with the ID of a gateway-originated request (`server/discover`, re-check `tools/list`), to confuse the client | Outstanding-request tracking (client-to-server always; server-to-client too under 2025-11-25); gateway-originated requests use a reserved ID namespace and are never forwarded; unmatched responses are dropped and audited | FR-031 | Low |
| T-05 | TB3 | Tampering | **2025-11-25 only:** server-initiated requests (sampling, elicitation, roots) used to inject content or extract data | v0.1: passed through, **audited**, and flagged in `audit tail`; enforcement planned for v0.2. Under 2026-07-28 the same capability arrives as MRTR and is covered by T-16 | FR-026 | Medium (accepted for v0.1) |
| T-06 | TB3 | Tampering | **Behavioral rug pull:** definition stays the same but the tool's behavior changes | Out of scope for pinning (definitions only); argument policy and result redaction limit impact | FR-024, FR-025 | Medium (AR-4) |
| T-07 | TB3 | Evasion | Payloads crafted to slip past analyzers (paraphrase, splitting across fields, base64) | Layered defense: pinning and policy don't depend on detection; adversarial corpus grows with each bypass | FR-006, FR-022 | Medium (AR-5) |
| T-08 | TB4 | Tampering | Pins, policies, or config modified to approve a malicious tool | File permission checks at startup (warn if group- or world-writable); every pin change is audited; container wrapping keeps the upstream away from the files | FR-026 | **High without container** (AR-2) |
| T-09 | TB4 | Repudiation | Audit records edited or deleted | SHA-256 hash chain; `audit verify`. Full chain rewrite or tail truncation is detectable only with an external anchor (v0.2 signed checkpoints) | FR-026, NFR-006 | Medium (AR-6) |
| T-10 | TB4 | Info disclosure | Secrets written into the audit log | Redact before logging; store argument digests rather than raw values by default | FR-025, FR-026 | Low |
| T-11 | TB5 | Spoofing | **Terminal escape injection:** tool text containing ANSI escapes or bidi controls makes a diff or approval prompt show something other than the truth | All untrusted text printed by the CLI goes through `termsafe` (escapes rendered visibly) | FR-029 | Low |
| T-12 | TB5 | Spoofing | Approval prompt hijack: prompts read from stdin, which carries MCP traffic; or, in a terminal-based agent, a prompt on the shared terminal corrupts the agent's interface and races it for keystrokes | v0.1 has **no interactive prompts**: `ask` = deny with an `approval_required` audit record; approval happens out of band through the CLI. (GUI clients launch servers with no terminal at all, so a terminal prompt could not work there anyway.) | FR-023 | Low |
| T-13 | TB1 | Elevation | **Bypass:** the agent is configured to launch the server directly, not through Bulwark | Documented; `bulwark doctor` (later) checks known client configs | — | Medium (AR-3) |
| T-14 | TB2 | Tampering | Supply-chain compromise of Bulwark or its dependencies | Pinned `go.sum`, `govulncheck` and dependency review in CI, SBOM, signed releases | NFR-012, NFR-015 | Low |
| T-15 | TB2 | DoS | Policy engine error or panic leaves calls unchecked | Fail closed (NFR-005); panics in interceptors are recovered and become denials | NFR-005 | Low |
| T-16 | TB3 | Info disclosure | **MRTR solicitation:** an `input_required` result asks the user or model for a secret or file contents, and the retried call carries the answer back to the server, bypassing checks that only look at ordinary arguments | Retry treated as a new `tools/call`: pin check, secret scan of `inputResponses`, policy with `input.request` (FR-035); input-request text analyzed and audited (FR-034) | FR-034, FR-035 | Medium (non-secret-shaped data still passes if policy allows the call) |
| T-17 | TB1/TB3 | Evasion | **Revision confusion:** a message in an older, unknown, or mixed revision is shaped so that Bulwark's interceptors miss it (for example server metadata arriving through `initialize` when Bulwark expects `server/discover`, or a change notification in the other revision's form) | Per-message revision detection; both supported revisions map onto one internal model so every control applies to both; unsupported revisions rejected in `enforce`; compatibility subset of the suite runs under 2025-11-25; under 2026-07-28, server-originated requests and `input_required` on non-MRTR methods are treated as violations | FR-036 | Low |
| T-18 | TB3 | Evasion | **Pin evasion through unhashed fields:** a server changes or poisons a tool field that the fingerprint does not cover (`icons`, `_meta`, a field from a newer revision) | Whole-object fingerprint with an explicit, audited exclude list (empty by default); unknown fields are kept and hashed, never dropped | FR-021, FR-028 | Low |
| T-19 | TB4 | Info disclosure | **Policy as an exfiltration path:** a policy file (malicious, or copied carelessly) uses OPA network or runtime built-ins such as `http.send` to send decision inputs, which include arguments, to a remote host, or reads the environment | Policies compiled with an OPA capabilities set that removes network and runtime built-ins; loading a policy that uses them fails (ADR-0004) | NFR-014 | Low |

### 7.5 Attack suite threats
| ID | Threat | Mitigation | Requirement |
|---|---|---|---|
| T-L1 | Lab server touches the network or real files | No network code in lab servers; suite runs in a network-disabled job; all writes confined to a temp directory | FR-002, NFR-003 |
| T-L2 | Someone configures a lab server in a real agent by mistake | `bulwark-lab` refuses to start without `BULWARK_LAB=1`; `LAB ONLY` banner on stderr; tool descriptions carry a visible lab marker outside the attack payload | FR-008 |
| T-L3 | Lab code is reused as an attack toolkit | Only publicly documented techniques; canaries only; no evasion tuning against real products | Hard rule 4 |

### 7.6 Accepted risks (stated in the README's "Limitations" section)
| ID | Risk | Why accepted | Guidance |
|---|---|---|---|
| AR-1 | A malicious stdio server is local code running as the user. It can read files or use the network **directly**, without going through MCP | Bulwark controls the agent-mediated channel; it isn't a sandbox | Run untrusted servers in a container: `bulwark wrap -- docker run -i --rm --network none <image>` |
| AR-2 | The same server can modify Bulwark's state files (T-08) | Same as AR-1 | Container wrapping; store state outside any directory mounted into the container |
| AR-3 | Bypass through misconfiguration (T-13) | Local tool; can't control the client | Documentation; `doctor` check later |
| AR-4 | Tool behavior isn't pinned, only definitions (T-06) | Behavior can't be fingerprinted from the protocol | Argument policy, redaction; taint tracking in v0.2 |
| AR-5 | Analyzers can be evaded (T-07) | Detection is never complete | Pinning and policy work regardless of detection |
| AR-6 | The audit chain can be rewritten wholesale by someone with write access (T-09) | Needs an external anchor | Signed checkpoints in v0.2 |
| AR-7 | Prompt injection itself isn't prevented | NG1: Bulwark limits damage | — |
| AR-8 | Prompts, resources, and MRTR input requests are **analyzed and audited but not pinned or blocked** in v0.1 (CH-4…CH-6) | Keeps v0.1 small; tool definitions and server metadata are the channels the model sees on every session | Review findings with `audit tail`; pinning and blocking for these channels in v0.2 |
| AR-9 | Injected instructions inside tool results, resource contents, error messages, or notifications are **not detected** in v0.1 (CH-3, CH-5, CH-8, CH-9); only secrets are redacted | Detecting injection in arbitrary content needs the classifier tier (v0.3); detection is never complete (AR-5) | Egress policy and redaction limit what a hijacked agent can send (M-4); taint tracking in v0.2 |
| AR-10 | **Path checks are lexical.** `fs_path` is cleaned as a string; Bulwark cannot see the server's filesystem, so symlinks, case-insensitive filesystems (default on macOS), Unicode-normalizing filesystems, and container mounts can make a path that passes the check resolve somewhere else | Resolving paths requires the server's view of the filesystem, which a gateway does not have | Run file servers in a container that mounts only the workspace; treat path rules as defense in depth, not containment |
| AR-11 | **Exfiltration through allowed destinations.** An egress allowlist cannot stop data sent to an allowed host that accepts user content (an issue tracker, a paste service, a shared document), or encoded in allowed arguments (paths, query strings, file names) | Policy constrains where data goes, not what it means | Keep allowlists narrow; secret redaction (FR-025) catches secret-shaped data; taint tracking in v0.2 blocks egress after sensitive reads |

### 7.7 Security requirements derived from this model
These were added to §2 in v0.6: **FR-028** (strict parsing, forward what was inspected), **FR-029** (terminal-safe output), **FR-030** (verify before call), **FR-031** (request ID isolation), **FR-008** (lab binary guard; first drafted as FR-032 and renumbered in v0.8 to fit the suite ID range), **NFR-013** (resource limits), **NFR-014** (no network listeners or connections), **NFR-015** (dependency hygiene). Added in v0.7 from the design 02 review: **FR-033** (server metadata pinning), **FR-034** (analysis of prompts, resources, and MRTR input requests), **FR-035** (MRTR retries as full calls), **FR-036** (revision handling); FR-003, FR-021, FR-025, and FR-031 amended.

## 8. AI/ML design 📝 (seed notes)

- **Where AI is used:** only for *scoring* text (tool descriptions and results) for injection likelihood. All enforcement is deterministic policy, so the security boundary does not depend on a model behaving correctly.
- **Tiered inspection:** tier 0 regex/heuristics (always on, under 1 ms) → tier 1 a small local classifier (for example a fine-tuned DeBERTa-class prompt-injection model; `VERIFY:` current best open models and licenses) → tier 2 an optional LLM-as-judge for high-risk sessions (off by default, NFR-007).
- **Evaluation datasets:** the lab corpus (poisoned definitions, injected results), public prompt-injection datasets (`VERIFY:` licenses), and a benign corpus of real servers' tool definitions and typical results.
- **Metrics:** precision/recall/F1 per tier, FPR on benign traffic, latency per tier, and the attack suite (§10.3) with the classifier enabled.
- **Failure modes:** false negatives (mitigated by taint containment), false positives (mitigated by `warn` mode and policy thresholds), model drift with new attack styles (refresh the corpus each release).
- **Fallback:** if the classifier is unavailable, tier 0 plus policy continue. Behavior is set by `on_classifier_error`.

**Questions to resolve**
1. Train or fine-tune your own classifier (strong portfolio signal; ML cost) or integrate an existing one (faster)?
2. Is tier 2 (LLM-as-judge) worth including at all, given privacy and latency?

---

## 9. Observability and operations 📝
Seed: structured logs, Prometheus metrics (decisions by type, latency histograms, findings by analyzer), OTel traces spanning client request → upstream call, health endpoints, hot reload of policies.

## 10. Testing and evaluation strategy 🌱

### 10.1 Test pyramid
Unit (analyzers, canonicalization, policy adapters) · property-based tests and Go native fuzzing (JSON-RPC parser, framing, re-serialization round trip; a short fuzz run on every PR, a longer one nightly) · integration (the official Go SDK client and example servers, pinned by version) · end-to-end (replay client + lab servers through the `bulwark` binary). No test uses a real AI client application or a human (NFR-002).

### 10.2 NFR verification
Every NFR is checked by a CI job (NFR-002): load/latency test (NFR-004), fault injection (NFR-005), audit tamper tests (NFR-006), network-isolated suite run (NFR-003, NFR-007), double-run determinism check (NFR-008), pipeline timing (NFR-009), OS matrix (NFR-010), scripted quickstart (NFR-011), and release signing (NFR-012).

### 10.3 Attack suite
The attack scenarios are built **first** (M1, see §12). Each one starts as a test that the attack succeeds, and each Gateway feature is finished when its scenario is detected under `warn` and blocked under `enforce`, by the control the manifest names.

`lab/` contains deliberately malicious, **harmless** MCP servers. "Exfiltration" goes to the observation log file (§4.2) and "secrets" are fake canaries. Every scenario works with a single upstream server, matching v0.1 scope. All scenarios run under revision 2026-07-28; L-01, L-02, and L-07 also run under 2025-11-25 to cover the compatibility path (FR-036).

| Scenario | Attack (replayed) | Observables under `none` | Blocked in v0.1 by (one control per run) | Later control |
|---|---|---|---|---|
| L-01 Poisoned description | Hidden `<IMPORTANT>` instruction to read a canary file and pass it to another tool | `poison_delivered`, `canary_exfiltrated` | Analyzer finding → tool hidden (FR-022); path policy (FR-024) | Classifier (v0.3) |
| L-02 Rug pull | Tool definition changes after the N-th call | `poison_delivered` after change | Pin mismatch → quarantine (FR-021) | — |
| L-03 Shadowing | One tool's description tells the agent to BCC an attacker address whenever it uses the server's `send_email` tool | `poison_delivered`, `forbidden_call_executed` | Cross-reference analyzer (FR-022); recipient-domain policy (FR-024) | Cross-server shadowing with aggregation (v0.2) |
| L-04 Indirect injection | A tool result contains instructions to send a canary to an external URL | `canary_exfiltrated` | Egress domain allowlist (FR-024); secret redaction in arguments (FR-025) | Taint tracking (v0.2) |
| L-05 Argument side channel | Schema adds a free-text `context` parameter that solicits secrets | `canary_exfiltrated` | Side-channel schema analyzer (FR-022); argument redaction (FR-025) | — |
| L-06 Unicode smuggling | Unicode Tag-block characters encode hidden instructions | `poison_delivered` | `unicode.hidden` analyzer (FR-022) | — |
| L-07 Poisoned server instructions | Server `instructions` (from `server/discover`, or `initialize` under 2025-11-25) tell the agent to read a canary file and send it out; tool definitions are clean | `poison_delivered` | Metadata analyzer finding → instructions stripped (FR-033) | Prompt and resource pinning (v0.2) |
| L-08 MRTR solicitation | A tool answers with `input_required`, asking for "your API key to continue"; the scripted retry supplies a canary in `inputResponses` | `canary_exfiltrated` | Secret scan of `inputResponses` + policy on the retry (FR-035); input-request finding (FR-034) | Approval broker (v0.2) |

**Attribution, so a test cannot pass for the wrong reason (FR-004):** each "Blocked in v0.1 by" entry above is a separate control. Where a row lists two, the scenario runs once per control with only that control enabled. Canaries come in two shapes: **secret-shaped** (`AKIAEXAMPLE…`, matched by the redaction rules) and **plain** (`canary-plain-…`, a value a unit test proves no secret rule matches). For example, L-04 uses a plain canary to prove the egress allowlist, and a secret-shaped canary sent to an *allowed* host to prove redaction. The CI results table shows which control fired.

**Replay, not live agents:** each scenario runs with the replay client under `none`, `bulwark-warn`, and `bulwark-enforce`, and asserts the expected observables (FR-004). The suite runs on every PR (FR-005). Optional live-model runs are a later feature (FR-046). Existing public resources (`VERIFY:` "Damn Vulnerable MCP Server", MCPTox, MCP-SafetyBench) are reused where licenses allow, mainly as sources of attack patterns and detection corpora.

---

## 11. Deployment and packaging 📝
Seed: local mode (single binary wrapping stdio servers, configured in the agent's MCP config), central mode (container behind TLS, Postgres state, OIDC for admin), Helm chart later. Release signing with Sigstore/cosign, SBOM per release, SLSA provenance via GitHub Actions.

## 12. Milestones and roadmap 🌱
| Milestone | Scope | Exit criteria |
|---|---|---|
| M0 | Design approved | Design review checklist passed |
| M1 | **Attack suite + transparent stdio proxy (both revisions) + audit log** | L-01…L-08 run in CI under all conditions; attacks succeed under `none` and (as expected at this stage) also through the passthrough proxy; network-isolation test passes; audit chain verifies |
| M2 | Pinning (tools and server metadata) + static analyzers on all channels + CLI + detection corpora | L-01, L-02, L-03, L-06, L-07 detected under `warn` and blocked under `enforce`, with the expected control attributed; detection rate and false-positive rate reported in CI |
| M3 | Policy engine + argument constraints + secret redaction + MRTR retry checks + demo + release pipeline; **v0.1 release** | All eight scenarios detected under `warn` and blocked under `enforce`, each control attributed; NFR-004 met; signed release with SBOM; one-command demo; launch write-up drafted for the maintainer to publish |
| M4 | Streamable HTTP + multi-server aggregation + taint tracking + approval broker; **v0.2** | New scenarios for HTTP and taint pass |
| M5 | Classifier tier (CPU, in CI) + OTel/OCSF export + optional live-model mode; **v0.3** | Classifier corpus results in CI |

### 12.1 Delivery estimate and cut line
The review budget is about one 30-minute PR per week (C-2). Each spec is one spec PR plus two or three code PRs, so the 8 v0.1 specs need about 24–32 review slots: **roughly 6–8 months to v0.1**. Already cut from v0.1 to fit: interactive `ask` prompts (FR-023), entropy-based secret detection (FR-025), and a separate audit spec (merged into spec 002). If the project falls behind, cut next, in this order:

1. macOS from CI except at release (NFR-010 becomes "tested at release")
2. The container form of the demo (FR-007 keeps `make demo` with the release binary)
3. Analysis of resource contents and prompts (FR-034 narrows to MRTR input requests; AR-8 widens)
4. The 2025-11-25 compatibility subset (FR-036 keeps rejecting unsupported revisions; the compatibility path moves to v0.2)

Nothing that backs a README claim is on this list: each cut removes a claim along with the work.

**Why attacks first:** every protection starts as a failing attack test and is finished when that test passes. This is test-driven development applied to security, and it means the README's claims are all backed by CI ([ADR-0001](docs/adr/0001-lab-first-roadmap.md), amended by [ADR-0002](docs/adr/0002-gateway-with-attack-suite.md)).

## 13. Alternatives considered
| Decision | Chosen | Alternatives | Where |
|---|---|---|---|
| Positioning | Gateway + deterministic attack suite | Live-model benchmark; gateway only; benchmark only | [ADR-0002](docs/adr/0002-gateway-with-attack-suite.md) |
| Language | Go | Python, TypeScript, Rust | [ADR-0003](docs/adr/0003-implementation-language.md) |
| Policy engine | OPA/Rego with a default-deny combiner | Cedar, custom YAML, Go plugins | [ADR-0004](docs/adr/0004-policy-engine.md) |
| Deployment shape (v0.1) | One process per wrapped server | Aggregating gateway (v0.2) | §4, decision 9 |
| Lab sink | Observation log file | Loopback HTTP listener (needs networking in tests) | §4.2, decision 10 |
| Rug-pull re-check | Gateway-initiated `tools/list` when stale (notification, `ttlMs`, max age); every call opt-in | Every call by default (doubles upstream traffic, disturbs stateful servers, little extra protection); notifications only (misses servers that never notify) | §4.4, decision 11 |
| Forwarding | Re-serialize the inspected message | Forward original bytes (parser-differential risk, T-01) | §7.4, decision 12 |
| Protocol revisions | 2026-07-28 primary + 2025-11-25 compatibility, revision-aware, no translation | 2026-07-28 only (breaks with clients and servers still on 2025-11-25); 2025-11-25 only (outdated at launch); translating between revisions (large, error-prone surface) | §1.3, decision 14 |
| Fingerprint scope | Whole object with an explicit exclude list | Fixed include list of fields (new or overlooked fields bypass pinning, T-18) | §5.1, decision 15 |
| Non-tool channels | Pin + strip server metadata; analyze and audit prompts, resources, MRTR requests | Tool definitions only (leaves `instructions` open, B2); pin and block every channel in v0.1 (too large for the MVP) | §4.5, decision 16 |
| Policy subject | Server identity + pin status + configured argument roles | Tool name and argument names alone (server-controlled, S2 in the design 02 review) | §5.3, decision 18 |
| `ask` in v0.1 | Deny with an `approval_required` audit record | `/dev/tty` prompt (unusable in GUI clients, conflicts with terminal agents) | §7.4 T-12, decision 19 |
| Suite assertions | Observables + attributed control, one run per control | Observables only (a test can pass because a different control fired) | §10.3, decision 20 |
| MRTR retries | New `tools/call` through the full pipeline | Treat as continuation of an already-approved call (answers bypass policy, T-16) | §4.4, decision 17 |

## 14. Decision log and open questions

### 14.1 Decision log
| # | Decision | Rationale | ADR | Date |
|---|---|---|---|---|
| 1 | Attacks first: attack scenarios are built before the features that block them | Test-driven security; every claim backed by CI | [ADR-0001](docs/adr/0001-lab-first-roadmap.md) (amended) | 2026-11-26 |
| 2 | Gateway with a deterministic attack suite; no live-model benchmark in v0.1 | Portfolio purpose, $0 budget, and no maintainer time for experiments; evidence differentiates in a crowded field | [ADR-0002](docs/adr/0002-gateway-with-attack-suite.md) | 2026-11-26 |
| 3 | v0.1 Gateway is stdio-only with one upstream server | Cuts the MVP to a size one person can deliver; covers the local-developer use case | — | 2026-11-26 |
| 4 | $0 budget and fully automated testing: OSS dependencies, GitHub Free, all verification in CI | Maintainer constraints | — | 2026-11-26 |
| 5 | Use MCPTox poisoned tool definitions as analyzer test data (license permitting) | Deterministic detection metric comparable with published research | — | 2026-11-26 |
| 6 | Sampling/elicitation passed through and audited, not enforced, in v0.1. *Amended v0.7:* applies to 2025-11-25 server-initiated requests; under 2026-07-28 these arrive as MRTR and the retry is checked (decision 17) | Keeps the MVP small; still visible in audit logs | — | 2026-11-26 |
| 7 | Working agreement: Claude drafts with recommendations applied; maintainer reviews by PR | Maintainer has 1–2 h/week | — | 2026-11-26 |
| 8 | Go for gateway, lab, and suite; MCP baseline 2026-07-28 | Single-binary releases, native OPA, stable official SDK | [ADR-0003](docs/adr/0003-implementation-language.md) | 2026-11-26 |
| 9 | One gateway process per wrapped server in v0.1 | Simplest model; matches how MCP clients launch stdio servers | — | 2026-11-26 |
| 10 | Lab sink is an observation log file, not a network listener | Lets the suite run with networking fully disabled | — | 2026-11-26 |
| 11 | Verify-before-call in `enforce` mode. *Amended v0.8:* re-check when stale (change notification, `ttlMs`, or `pin_recheck_max_age`, default 300 s); every call is opt-in | Definitions reaching the model are already checked on every `tools/list`; the re-check only signals an implementation change, and a malicious server can defeat it (T-06), so it is not worth an extra round trip on every call | — | 2026-11-26 |
| 12 | Forward re-serialized inspected messages; reject duplicate keys | Closes parser-differential bypasses (T-01) | — | 2026-11-26 |
| 13 | OPA/Rego with default-deny combiner and gateway-derived attributes | Expressive, testable, widely recognized | [ADR-0004](docs/adr/0004-policy-engine.md) | 2026-11-26 |
| 14 | Support 2026-07-28 (primary) and 2025-11-25 (compatibility); detect the revision per message; no translation; reject unsupported revisions in `enforce` | 2026-07-28 removed the handshake and server-initiated requests; both revisions will be in use at launch | [ADR-0003](docs/adr/0003-implementation-language.md) (amended) | 2026-11-26 |
| 15 | Fingerprint the whole tool object (and server metadata), with an explicit exclude list that is empty by default | Fields outside a fixed include list would bypass pinning (T-18) | — | 2026-11-26 |
| 16 | Inventory all model-visible channels (§4.5); pin and strip server metadata in v0.1; analyze and audit prompts, resources, and MRTR requests; state the rest as accepted risks AR-8, AR-9 | Closes the `instructions` gap without pinning every channel in the MVP; keeps the §1.1 claim honest | — | 2026-11-26 |
| 17 | An MRTR retry is a new `tools/call` through the full pipeline | The retry carries server-requested data back to the server (T-16) | — | 2026-11-26 |
| 18 | Policy input carries gateway-supplied server identity and pin status; derived attributes only for configured, pinned argument roles; OPA network and runtime built-ins removed | Tool names and argument meanings are server-controlled; policies must not make network calls (T-19) | [ADR-0004](docs/adr/0004-policy-engine.md) (amended) | 2026-11-26 |
| 19 | No interactive prompts in v0.1; `ask` = deny with an `approval_required` audit record | GUI clients have no terminal; terminal agents share theirs (T-12) | [ADR-0004](docs/adr/0004-policy-engine.md) (amended) | 2026-11-26 |
| 20 | Suite asserts the control that fired; multi-control scenarios run once per control; plain and secret-shaped canaries; `warn` = detected, `enforce` = blocked | Stops tests passing for the wrong reason | — | 2026-11-26 |
| 21 | PR CI is Linux only; macOS on merges to `main` and releases | macOS runners cost about 10× Linux on a private repo (C-4) | — | 2026-11-26 |
| 22 | NFR-004 gated on an in-process benchmark; end-to-end latency reported only | Shared runners are too noisy for an end-to-end latency gate (NFR-008) | — | 2026-11-26 |
| 23 | v0.1 is 8 specs; interactive `ask` and entropy detection cut; ordered cut line in §12.1 | About 6–8 months at one review per week | — | 2026-11-26 |
| 24 | Lossless re-serialization: exact numbers, unknown fields kept, lone surrogates rejected; round-trip property and fuzz tests | Re-serializing through floats or dropping fields would corrupt IDs and break transparency (FR-028) | — | 2026-11-26 |

### 14.2 Open questions
- Q1 Deny response format: JSON-RPC error vs. tool result with `isError: true` (design 03; decided from the spec and how the official SDKs' client code surfaces each form to the model, checked by automated tests against the SDK client, not by manual testing with real apps)
- Q2 Pin store location and format details; server identity for stdio (design 03)
- Q3 Classifier strategy (v0.3)

## 15. Spec backlog (draft)
v0.1 is planned as **8 specs** (merged from 10 in v0.8 to fit the review budget, §12.1).

| Spec | Title | Traces to | Milestone |
|---|---|---|---|
| 001 | Attack suite: lab scenarios L-01…L-08, manifests, observation log, lab guard, replay client (both revisions), runner, CI skeleton and results table | FR-001…FR-005, FR-008, NFR-001, NFR-002, NFR-003, NFR-008, NFR-009, NFR-010 | M1 |
| 002 | stdio proxy: strict JSON-RPC, request IDs, revision handling; hash-chained audit log + `audit verify/tail`; terminal-safe output | FR-020, FR-026, FR-028, FR-029, FR-031, FR-036, NFR-004, NFR-006, NFR-007, NFR-013, NFR-014 | M1 |
| 003 | Fingerprinting (tools + server metadata) + pin store + modes + verify-before-call | FR-021, FR-030, FR-033 | M2 |
| 004 | Static analyzers (first 4) on all channels + detection corpora | FR-006, FR-022, FR-034 | M2 |
| 005 | `tools` CLI (list/diff/approve/reject) | FR-027 (reuses FR-029 from spec 002) | M2 |
| 006 | Policy engine + argument roles + MRTR retry checks + `policy test` | FR-023, FR-024, FR-035, NFR-005 | M3 |
| 007 | Secret detection + redaction | FR-025 | M3 |
| 008 | One-command demo + release pipeline (SBOM, signing, vuln scan) | FR-007, NFR-011, NFR-012, NFR-015 | M3 |
| 009 | Streamable HTTP + multi-server aggregation | FR-040, FR-041 | M4 |
| 010 | Taint tracker + taint-aware policy | FR-042 | M4 |
| 011 | Approval broker | FR-043 | M4 |
| 012 | Injection classifier tier | FR-044 | M5 |
| 013 | OTel + OCSF exporters | FR-045 | M5 |
| 014 | Optional live-model mode | FR-046 | M5 |

## Appendix: References
- Model Context Protocol specification, revision 2026-07-28: modelcontextprotocol.io/specification/2026-07-28; source files (changelog, `schema/2026-07-28/schema.ts`, stdio transport, MRTR pattern, `server/discover`) checked in the specification repository github.com/modelcontextprotocol/modelcontextprotocol on 2026-11-26
- MCP blog, "The 2026-07-28 Specification": blog.modelcontextprotocol.io/posts/2026-07-28
- Model Context Protocol specification, revision 2025-11-25 (compatibility target)
- Official MCP Go SDK: github.com/modelcontextprotocol/go-sdk (v1.7.0)
- Open Policy Agent: openpolicyagent.org
- OWASP GenAI Security Project: Top 10 for LLM Applications 2026; Top 10 for Agentic Applications (Dec 2025): genai.owasp.org
- Cloud Security Alliance, *MCP Tool Poisoning and Rug Pull Attacks* whitepaper (May 2026)
- arXiv 2603.22489: study of tool-poisoning defenses in MCP clients (2026)
- Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), 2025, likely arXiv 2503.18813 (`VERIFY:` ID and author affiliations)
- Simon Willison, "The lethal trifecta for AI agents" (2025)
- RFC 8785 JSON Canonicalization Scheme; JSON-RPC 2.0 specification
- MITRE ATLAS: atlas.mitre.org
