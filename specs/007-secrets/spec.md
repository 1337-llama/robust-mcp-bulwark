# Spec 007: Secret detection and redaction

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-025 (also FR-035's secret check, NFR-004); threats T-10; mitigations M-4, M-9 |
| Milestone | M3 |
| Depends on | Spec 002 (pipeline, audit), spec 004 (string walker, excerpts), spec 006 (block forms, `-32011`) |

## Summary
Bulwark looks for well-known secret formats in what the agent sends out and in what the server sends back:
- **Outbound** (tool arguments, MRTR answers): a match **blocks** the request by default. Silently editing an argument would change what the tool does.
- **Inbound** (results, errors, resource text): a match is **replaced** with a visible `[REDACTED:<rule>]`, so the model can tell something was removed.

The rules are a small set of public patterns, taken from gitleaks (MIT), not written from scratch. Three spec 001 attack runs become required: L-04 run 2, L-05, and L-08 run 1, all `secrets:aws-access-key`.

## User stories
- As a **developer**, I want a hijacked agent that pastes my AWS key into a tool call to be stopped before the key leaves.
- As a **security reviewer**, I want keys in tool output masked before the model sees them, and the masking to be visible.
- As an **IR analyst**, I want the audit log to say which rule matched where, without containing the secret.

## Acceptance criteria (EARS)

**Rules**
- **AC-1:** THE rule set SHALL be the following regexes, copied from gitleaks `config/gitleaks.toml` at commit `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` (MIT), embedded as data, and compiled with Go's `regexp` (RE2):

  | Rule ID (`secrets:<id>`) | gitleaks rule(s) | Severity |
  |---|---|---|
  | `aws-access-key` | `aws-access-token` | high |
  | `github-token` | `github-pat`, `github-oauth`, `github-app-token`, `github-fine-grained-pat` | high |
  | `slack-token` | `slack-bot-token`, `slack-user-token`, `slack-legacy-token` | high |
  | `google-api-key` | `gcp-api-key` | high |
  | `stripe-live-key` | `stripe-access-token`, restricted to the `live` prefix | high |
  | `private-key` | `private-key` | high |
  | `jwt` | `jwt` | medium |

  gitleaks' entropy thresholds are not used (DESIGN.md §5.5: patterns only in v0.1). Each rule SHALL have positive and negative unit tests, including the AWS documentation example `AKIAIOSFODNN7EXAMPLE`.
- **AC-2:** THE suite's canaries SHALL be checked against this rule set: every `secret` canary matches `aws-access-key`, and every `plain` canary matches no rule. This replaces spec 001's interim pattern list (spec 001 AC-31 is amended in this PR).

**Where (FR-025)**
- **AC-3:** THE scanner SHALL apply the rules to every **decoded** string value and object key in:
  - client → server: `tools/call` `arguments`, and `inputResponses` on MRTR retries of all three methods (FR-035)
  - server → client: `tools/call` results (`content[].text`, every string in `structuredContent`), error `message` and `data`, and `resources/read` text contents

  It reuses spec 004's walker, so JSON escapes such as `AKIA` can't hide a match. Binary and base64 blobs are not scanned (AR-9).

**Actions (§6.3 `secrets.requests`, `secrets.results`)**
- **AC-4:** WHILE `mode` is `enforce`, a request match SHALL act per `secrets.requests`:
  - `deny` (default): block, with control `secrets:<rule>`. `tools/call` gets the tool result of spec 006 AC-8; `prompts/get` and `resources/read` retries get `-32011` (DESIGN.md §6.6).
  - `redact`: replace the match in the forwarded message with `[REDACTED:<rule>]`.
  - `audit`: forward unchanged and record.

  This check runs before and independent of the policy (DESIGN.md §5.6, layer 1).
- **AC-5:** WHILE `mode` is `enforce`, a result match SHALL act per `secrets.results`:
  - `redact` (default): replace every match with `[REDACTED:<rule>]`, then re-serialize.
  - `audit`: forward unchanged and record.
- **AC-6:** WHILE `mode` is `warn` or `learn`, matches SHALL be recorded and the message forwarded unchanged, consistent with "nothing is blocked" in `warn` (§6.1).
- **AC-7:** WHERE several rules match overlapping text, THE longest match SHALL win, and ties go to the rule listed first in AC-1. Every match in a string is replaced, so no fragment of a secret is left.

**Audit (T-10)**
- **AC-8:** EACH match SHALL add a finding `{analyzer: "secrets", rule, severity, location (JSON Pointer)}` to the message's audit record, plus the control when it blocked. The excerpt SHALL be the redacted string, so **no audit record, finding, or stderr line contains a matched secret**. A test scans the whole audit directory after the suite for each secret canary.
- **AC-9:** THE redaction function SHALL be the one used for spec 004's excerpts (spec 004 AC-1), so there is a single implementation.

**Suite and performance**
- **AC-10:** THE `pending: spec-007` expectations SHALL become required, and the suite SHALL pass on Linux and macOS:

  | Run | `enforce` | `warn` |
  |---|---|---|
  | L-04 run 2 (secret to the allowed host) | `canary_exfiltrated: false` | `true`, control fired |
  | L-05 (`translate(context = secret)`) | `canary_exfiltrated: false` | `true`, control fired |
  | L-08 run 1 (secret in the requested key) | `canary_exfiltrated: false` | `true`, control fired |

  Each run's control is `secrets:aws-access-key`, under the spec 001 generated configuration (`secrets.requests: deny`, everything else off or `audit`).
- **AC-11** (NFR-004): THE spec 002 benchmark SHALL include a 64 KiB result and a tool call, both scanned. The 5 ms p95 gate SHALL still pass.

## Out of scope
- Entropy-based or generic "password = …" detection (v0.2; false positives).
- Notifications (logging, progress) and binary or base64 content (AR-9).
- A secret split across two strings or two messages. Each string is scanned on its own; this limit is stated in the README.
- Verifying that a match is a live credential: Bulwark never contacts a provider (NFR-014).

## Open questions
None.
