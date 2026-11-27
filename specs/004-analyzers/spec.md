# Spec 004: Static analyzers on all channels + detection corpora

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-006, FR-022, FR-034 (also FR-033's analyzer hook); threats T-02, T-05, T-07; mitigations M-1, M-3, M-5, M-8, M-9 |
| Milestone | M2 |
| Depends on | Spec 002 (pipeline, audit, termsafe), spec 003 (analyzer hook, `findings_at_approval`) |

## Summary
Four rule-based analyzers look for poisoning in everything a server can put in front of the model:
- `unicode.hidden`: hidden characters
- `text.imperative`: instructions aimed at the model
- `text.cross_reference`: one tool steering how another is used
- `schema.side_channel`: parameters that solicit secrets or context

On **tool definitions** and **server metadata**, a high-severity finding hides or strips the item in `enforce` mode, through spec 003's hook. On **prompts, resources, and MRTR input requests**, findings are recorded but nothing is blocked (AR-8).

The analyzers are measured honestly. Detection is measured against **485 published poisoned tool descriptions** (MCPTox, CC BY 4.0), and false positives against **benign tool definitions from the official MCP reference servers**. Both corpora are split into tuning and held-out halves, and CI reports results on the held-out half only. Four spec 001 attack runs become required: L-01, L-03, L-05, L-06, plus L-07's analyzer run.

## User stories
- As a **developer**, I want a poisoned tool to be hidden even if I approved it in `learn` mode before I knew better.
- As a **security reviewer**, I want detection and false-positive rates measured on data the rules were not tuned on, so the numbers mean something.
- As an **operator**, I want to accept a false positive by approving the tool, without switching the analyzer off for everyone.

## Acceptance criteria (EARS)

**Framework (FR-022)**
- **AC-1:** EACH finding SHALL carry: `analyzer`, `rule`, `severity` (`info`, `low`, `medium`, `high`), `channel` (`CH-1`…`CH-7`), `location` (a JSON Pointer, DESIGN.md §5.6), and `excerpt`. The excerpt is at most 120 characters, secret-redacted, and stored with every Cc/Cf/Zl/Zp code point escaped.
- **AC-2:** THE text extractor SHALL produce `(location, string)` pairs for each channel:
  - **CH-1, tools:** `name`, `title`, `description`, `annotations.title`, and in `inputSchema`/`outputSchema` every property **name**, `title`, `description`, `enum` and `default` string, at any depth, including `$defs`
  - **CH-2, metadata:** `instructions`, and `serverInfo` `name`, `title`, `version`, `description`
  - **CH-4, prompts:** the `prompts/list` `name`, `title`, `description`, and argument descriptions; `prompts/get` message text
  - **CH-5, resources:** the `resources/list` and template `name`, `title`, `description`, `uri`/`uriTemplate`
  - **CH-6, MRTR input requests:** elicitation `message` and `requestedSchema` texts; sampling message text and `systemPrompt`
  - **CH-7, legacy server requests:** the same fields as CH-6
- **AC-3** (T-02): EACH analyzer SHALL see each string twice: **raw**, and **normalized** (NFKC, then Unicode case folding, then removal of every Cf code point). A rule matches if it matches either form.
- **AC-4:** THE rules SHALL be data: one versioned YAML file embedded with `go:embed`, using Go's RE2 engine only (linear time; no backtracking constructs exist). Every rule SHALL list at least one positive and one negative example in the file, and a test SHALL run all of them.
- **AC-5:** Analysis results SHALL be cached by fingerprint (spec 003), so an unchanged tool or metadata is analyzed once per process. Strings longer than 64 KiB SHALL be analyzed up to 64 KiB, with an `analysis.truncated` finding (severity `low`).

**The four analyzers (DESIGN.md §5.4)**
- **AC-6 `unicode.hidden`:**
  - `high` for Unicode Tag characters (U+E0000–U+E007F) and bidi controls (U+202A–U+202E, U+2066–U+2069)
  - `medium` for other Cf code points (for example zero-width characters) and for Cc characters other than newline and tab
  - `medium` for a tool or server `name` mixing letters from more than one Unicode script (homoglyph names)
- **AC-7 `text.imperative`:** rules for model-directed instructions:
  - ignore or override earlier instructions
  - conceal actions from the user ("do not tell/mention/inform the user")
  - pseudo-system markup (`<IMPORTANT>`, `<SYSTEM>`, `[INST]`)
  - mandatory preconditions ("before using this tool, (first) read/call/send/write …")
  - role reassignment ("you are now …")

  Severity is `high` when an instruction co-occurs, in the same string, with a sensitive target: credential or key paths (`~/.ssh`, `id_rsa`, `.env`, `credentials`), secrets vocabulary, or an exfiltration verb with a URL or email address. Otherwise it is `medium`.
- **AC-8 `text.cross_reference`:** `low` when a string in one tool's definition names another tool of the same server (exact name match, quoted or bare). `high` when that string also matches a `text.imperative` rule. Under spec 003's view, "other tools" means the current listing.
- **AC-9 `schema.side_channel`:** `medium` for a parameter whose name is in the side-channel list (`context`, `notes`, `metadata`, `debug_info`, `conversation`, `history`, `previous_messages`, `system_prompt`, `sidenote`, and variants differing only in case or separators). `high` when that parameter's description solicits conversation content, credentials, file contents, or "everything".

**Channel behavior (FR-022, FR-033, FR-034)**
- **AC-10:** Findings on **CH-1 and CH-2** SHALL be passed to spec 003's hook. A `high` finding not listed in `findings_at_approval` hides the tool, or reduces the metadata, in `enforce` mode. The audit record's `controls` SHALL name `analyzer:<analyzer>/<rule>`.
- **AC-11:** Findings on **CH-4 to CH-7** SHALL be recorded and never cause a block (AR-8).
- **AC-12:** WHILE in `learn` mode, analyzers SHALL run and their findings SHALL be recorded. A `learn` approval SHALL NOT add them to `findings_at_approval` (spec 003 AC-14), so learning never silently accepts a poisoned tool.
- **AC-13:** THE configuration key `analyzers.enabled` SHALL select which analyzers run; `[]` disables all of them (spec 001 AC-27).

**Corpora (FR-006)**
- **AC-14:** `testdata/corpora/mcptox/poisoned.jsonl` SHALL contain all 485 poisoned tool descriptions from MCPTox's `pure_tool.json`. Each record holds:
  - `id` (the MCPTox key, for example `FileSystem_1`), `server`, `tool_name`, `paradigm`, `risk`, `description`
  - the source repository commit SHA

  It is converted by `tools/corpus mcptox`. A `NOTICE` file SHALL give the CC BY 4.0 attribution the license asks for: the MCPTox contributors, the paper citation (AAAI 2026, DOI 10.1609/aaai.v40i42.40895), the source repository URL, a link to the license, and a statement of the changes made (format conversion; content unchanged).
- **AC-15:** `testdata/corpora/benign/tools.jsonl` SHALL contain **at least 100** tool definitions captured by `tools/corpus benign`, which runs the official MCP reference servers (github.com/modelcontextprotocol/servers; MIT, moving to Apache-2.0) and records `tools/list`. The exact package versions are recorded. A `NOTICE` file gives attribution. Re-capturing is a scripted step done by Claude, never by the maintainer.
- **AC-16** (spec 002 AC-34): ALL corpus files SHALL be plain ASCII. Every non-ASCII code point is written as a JSON escape sequence (backslash, `u`, four hex digits), which is lossless, so the hidden-character check applies with no exemptions. A test SHALL show that decoding reproduces the source strings exactly.
- **AC-17:** EACH corpus SHALL be split once into **tuning** and **held-out** halves by the lowest bit of SHA-256(`id`). Rules are written and tuned against the tuning half only; this is stated in CONTRIBUTING.md. Both halves are checked in, and a test fixes the split.
- **AC-18:** CI SHALL report, on the **held-out** halves:
  - **detection rate:** poisoned items with at least one finding of severity ≥ `medium`
  - **hide rate:** poisoned items with at least one `high` finding
  - **false-positive rates:** benign items with a finding of severity ≥ `medium`, and with a `high` finding

  Results are broken down per analyzer, per MCPTox paradigm (Template-1/2/3), and per risk category, in the job summary and in `testdata/corpora/report.json`.
- **AC-19:** CI SHALL fail IF held-out detection or hide rates fall below, or false-positive rates rise above, the values in `testdata/corpora/baseline.json` (a ratchet). The baseline may change only in a PR that states why. The IDEA.md targets (≥ 90 % detection, ≤ 2 % false positives) are shown in the README next to the current values. **They are goals, not gates.** The README states honestly where the analyzers stand.

**Suite (spec 001 expectations become required)**
- **AC-20:** THE following runs SHALL drop `pending: spec-004` and pass, each with setup `{approve: all, approve_metadata: true}`:

  | Scenario | Control | `warn` | `enforce` |
  |---|---|---|---|
  | L-01 | `analyzer:text.imperative/*` | attack observables true; control fired | `poison_delivered: false` |
  | L-03 | `analyzer:text.cross_reference/*` | as above | `poison_delivered: false` |
  | L-05 | `analyzer:schema.side_channel/*` | as above | `poison_delivered: false`, `canary_exfiltrated: false` (the poisoned tool itself is hidden, so the call gets `-32602`) |
  | L-06 | `analyzer:unicode.hidden/*` | as above | `poison_delivered: false` |
  | L-07 | `analyzer:text.imperative/*` | as above | `poison_delivered: false` |

  For L-01, L-03, and L-07 in `enforce`, `canary_exfiltrated` and `forbidden_call_executed` are **not asserted**. The scripted replay still calls the *clean* tools, as a fixed script always would. That the poison never reaches the model is the property an analyzer provides, and the README says so. L-01's and L-03's policy runs (spec 006) assert the call-level blocks.
- **AC-21:** THE README results table SHALL show these cells, and the analyzer metrics with their targets.

**Performance**
- **AC-22** (NFR-004): THE spec 002 benchmark SHALL run with all four analyzers enabled and caching on, and the p95 < 5 ms gate SHALL still pass. A separate benchmark SHALL report cold (uncached) analysis time per tool definition, which is reported but not gated.

## Out of scope
The ML classifier (v0.3); detecting injection in tool **results** (AR-9, v0.3); blocking on prompts or resources (v0.2); the `tools` CLI that shows findings (spec 005).

## Open questions
None.
