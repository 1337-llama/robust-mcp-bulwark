# Spec 006: Policy engine, argument roles, MRTR checks, `policy test`

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-023, FR-024, FR-035, NFR-005 (also NFR-004, NFR-014); threats T-06, T-12, T-19; mitigations M-3, M-4, M-6, M-9 |
| Milestone | M3 |
| Depends on | Spec 002 (pipeline, audit, error forms), spec 003 (pin status), spec 005 (decision 39: `arg_roles` from configuration) |

## Summary
This spec makes Bulwark decide **whether a tool call may run**, using policies written in Rego (OPA). It adds four things:
- **Policy engine.** An embedded **baseline allow** grants every approved tool. Operators write `deny` rules to restrict calls, and a call no rule allows is denied.
- **Argument roles.** For arguments the operator labels as a file path, an outbound URL, or an email recipient, the gateway parses the value itself, so policies never re-implement path or URL parsing. A value that won't parse makes the restriction **deny**.
- **MRTR checks.** When a server asks for more input mid-call (2026-07-28), the client's answers come back in a retry. Bulwark blocks answers to questions that were never asked, and retries that match no question.
- **`bulwark policy test`.** It runs an operator's Rego tests with the same sandbox the gateway uses.

Four spec 001 attack runs become required: L-01 (`policy:fs-workspace-only`), L-03 (`policy:recipient-domain`), L-04 (`policy:http-allowlist`), and L-08 (`mrtr:unsolicited_response`).

## User stories
- As an **operator**, I want to say "this server's file tools stay inside `/workspace`" once, and have it hold even after the server adds a tool.
- As a **security reviewer**, I want a broken or slow policy to block, not allow.
- As a **policy author**, I want a typo in a policy to fail at load time, not to silently never fire.
- As an **IR analyst**, I want the audit record to name the rule that blocked a call.

## Acceptance criteria (EARS)

**Engine (FR-023, NFR-005, T-19)**
- **AC-1:** THE gateway SHALL embed OPA through `github.com/open-policy-agent/opa/v1/rego`, pinned in `go.mod` (v1.22.4 when this spec was written; OPA's `go.mod` needs Go ≥ 1.26). It loads every `*.rego` file in `policy.dirs` except `*_test.rego`, plus the embedded baseline module, all in package `bulwark.authz` and Rego v1 syntax.
- **AC-2:** THE policies SHALL be compiled with OPA's capabilities for the pinned version **minus every built-in marked `nondeterministic`**. On v1.22.4 that removes 11 built-ins, the list in DESIGN.md §5.6, checked by a golden test, so an OPA upgrade that changes the list is reviewed. A policy that uses a removed built-in (for example `http.send`) SHALL fail to load.
- **AC-3:** THE policies SHALL also be compiled against the decision-input JSON Schema (`schemas/policy-input.v1.json`, `additionalProperties: false` throughout) via `rego.Schemas`, so a reference to a field that doesn't exist (for example `input.derived.fs_paht`) fails to load.
- **AC-4:** IF any policy fails to load, THEN `wrap` SHALL refuse to start, **in every mode**, with exit code 1 and one `bulwark:` stderr line naming the file and error. A wrong policy would make `warn` results misleading too.
- **AC-5:** THE query SHALL be prepared once at startup, with strict built-in errors on. Each evaluation SHALL have a deadline of `policy.eval_timeout` (default 50 ms). IF evaluation errors, times out, or returns anything but sets of strings, THEN the decision SHALL be **deny**, control `policy:default-deny`, and the audit record's `reason` `eval_error` or `timeout`.
- **AC-6 (combiner):** THE decision SHALL be:
  1. any `deny` → deny; `controls` = `policy:<id>` for every deny ID, sorted
  2. else any `ask` → deny with `decision: approval_required`; controls as above for the ask IDs (FR-023, v0.1)
  3. else any `allow` → allow
  4. else deny, control `policy:default-deny`
- **AC-7:** WHERE `policy.baseline_allow` is `true` (the default), THE embedded module SHALL add `allow` entry `baseline-approved-tool` when `input.tool.pin_status == "approved"`. WHERE it is `false`, the module SHALL NOT be loaded.
- **AC-8:** THE gateway SHALL evaluate the policy for every `tools/call` that reaches the policy stage (after MRTR checks and the pin check, DESIGN.md §5.1). WHILE in `enforce` mode, a deny SHALL be returned as the tool result in §6.6, with the text `Blocked by MCP Bulwark (<control>). The call was not sent to the server.`, and the request SHALL NOT be forwarded. WHILE in `warn` or `learn` mode, the call SHALL be forwarded and the record SHALL carry the decision and controls.

**Decision input (FR-024)**
- **AC-9:** THE decision input SHALL follow DESIGN.md §5.6 and validate against `schemas/policy-input.v1.json`. `server` and `tool.pin_status` come from Bulwark, never from the server. `tool.arg_roles` comes from configuration (decision 39). `request.input_responses` is the retry's `inputResponses` object, or `null`. A test validates the input of every call in the suite against the schema.
- **AC-10:** THE configuration SHALL reject an `arg_roles` value other than `fs_path`, `egress_url`, or `recipient`.
- **AC-11 (derived values):** FOR each role, `derived.<role>` SHALL be a list with one element per string found in the arguments that carry that role: a string argument gives one element; an array argument gives one element per item; a declared argument that is **absent** from the call gives one `null` element, so omitting it can't skip the restriction. Arguments without a declared role produce nothing. Each element is an object, or `null` when the value doesn't parse:

  | Role | Element | `null` when |
  |---|---|---|
  | `fs_path` | `{"path": path.Clean(value)}` | not a string, not absolute, or contains NUL. Lexical only (AR-10) |
  | `egress_url` | `{"scheme", "host" (lowercased), "port" (string or `null`)}` from `net/url` | no scheme or host, or a non-ASCII host. Allowlists use the punycode form; there is no IDNA conversion (decision 41) |
  | `recipient` | `{"address", "domain"}`, both lowercased | not a string, not exactly one `@`, an empty side, or non-ASCII |

  `net/url` is a parser and opens nothing; the import ban (spec 002 AC-32) covers `net`, `net/http`, and `net/rpc`.
- **AC-12 (fail closed):** A restriction written with a named helper rule (`not path_ok(p)`) SHALL deny for a `null` element. The example and lab policies SHALL use this form. `bulwark policy test` fixtures SHALL show that it denies, and that the inline form (`not p.host in {...}`) does **not**, which is why the helper form is required (DESIGN.md §5.6).

**MRTR (FR-035, M-9)**
- **AC-13 (record):** WHEN a `tools/call`, `prompts/get`, or `resources/read` result has `resultType: "input_required"` under 2026-07-28, THE gateway SHALL record `{method, target (tool name, prompt name, or resource URI), requestState or absent, the inputRequests keys, time}`. The table holds 64 entries with a 10-minute TTL (injected clock), evicting the oldest first. Each entry produces an `mrtr_input_required` audit record. The result is forwarded unchanged.
- **AC-14 (retry):** A request of one of those three methods that carries `inputResponses` or `requestState` SHALL be treated as a **retry**. It SHALL be matched:
  - by method, target, and exact `requestState` when it has one
  - otherwise, to the most recent entry for that method and target whose keys include every `inputResponses` key

  Two such entries with different key sets make the retry ambiguous, and it is treated as unmatched. A matched entry is removed, so it answers one retry only.
- **AC-15 (checks):** An unmatched retry SHALL get control `mrtr:unmatched_retry`. A matched retry with an `inputResponses` key that its entry didn't request SHALL get `mrtr:unsolicited_response`. WHILE `mode` is `enforce` AND `mrtr.mode` is `enforce`, either one SHALL block the retry:
  - `tools/call`: the tool result of AC-8
  - `prompts/get`, `resources/read`: JSON-RPC error `-32011` with the message `Blocked by MCP Bulwark (<control>)` (DESIGN.md §6.6)

  Otherwise the retry is forwarded and the control recorded.
- **AC-16:** A `tools/call` retry that passes AC-15 SHALL continue through the pin check and the policy with `request.is_retry: true`. `prompts/get` and `resources/read` retries get no policy evaluation in v0.1 (AR-8). `requestState` SHALL be forwarded byte for byte; a test compares the bytes sent upstream with the bytes received.

**`policy test` (FR-027)**
- **AC-17:** `bulwark policy test [--policy-dir DIR]...` SHALL run every `*_test.rego` in the directories through OPA's test runner (`v1/tester`), compiled with the same capabilities, schema, and baseline module as the gateway. Exit code 0 if all pass, 3 if any fail, 1 if a policy fails to load.
- **AC-18:** `bulwark policy test --input FILE` SHALL evaluate one decision input and print the decision, the controls, and the deny, ask, and allow sets, with every string through `termsafe`.
- **AC-19:** THE repository SHALL ship `examples/policies/` with the three DESIGN.md §5.6 rules and their tests: each rule blocks **with the baseline allow on**, reports its ID, and denies on a `null` element. CI SHALL run `bulwark policy test` on `examples/policies/` and `lab/policies/`.

**Suite and performance**
- **AC-20:** THE lab policies `lab/policies/l01-fs-workspace-only.rego.tmpl`, `l03-recipient-domain.rego.tmpl`, and `l04-http-allowlist.rego.tmpl` SHALL each hold exactly one `deny` rule, so `controls_fired` is exact. The `pending: spec-006` expectations of L-01, L-03, L-04 (first run), and L-08 (run 2) SHALL become required, and the suite SHALL pass on Linux and macOS:

  | Run | `setup.arg_roles` | `enforce` | `warn` |
  |---|---|---|---|
  | L-01 `policy:fs-workspace-only` | `read_file: {path: fs_path}` | `canary_exfiltrated: false` | `true`, control fired |
  | L-03 `policy:recipient-domain` | `send_email: {to: recipient, bcc: recipient}` | `forbidden_call_executed: false` | `true`, control fired |
  | L-04 `policy:http-allowlist` | `http_post: {url: egress_url}` | `canary_exfiltrated: false` | `true`, control fired |
  | L-08 `mrtr:unsolicited_response` | none | `canary_exfiltrated: false` | `true`, control fired |
- **AC-21** (NFR-004): THE spec 002 benchmark SHALL include a `tools/call` evaluated against `examples/policies/`. The 5 ms p95 gate SHALL still pass.

## Out of scope
- Policy evaluation for `prompts/get` and `resources/read` (v0.2, AR-8).
- Hot reload: policies change when the client restarts the server (ADR-0004).
- Interactive `ask` prompts: these come with the approval broker (v0.2, T-12).
- IDNA conversion (decision 41).
- Symlink-aware path checks (AR-10).
- Secret detection: spec 007 builds `secrets:*`, including L-04's second run and L-08 run 1.

## Open questions
None.
