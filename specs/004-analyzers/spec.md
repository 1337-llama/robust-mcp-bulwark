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

The analyzers are measured honestly. Both corpora come from MCPTox (AAAI 2026, CC BY 4.0), built on the same 45 real-world servers:
- **detection** is measured against **485 published poisoned tool descriptions**
- **false positives** are measured against the **322 clean, authentic tool definitions** of the 42 servers whose upstream code has a permissive license (MCPTox's license doesn't cover third-party text, AC-14a)

Whole **servers** are held out, so near-duplicate attack templates can't leak across the split. CI reports results on the held-out half only. Four spec 001 attack runs become required: L-01, L-03, L-05, L-06, plus L-07's analyzer run.

## User stories
- As a **developer**, I want a poisoned tool to be hidden even if I approved it in `learn` mode before I knew better.
- As a **security reviewer**, I want detection and false-positive rates measured on data the rules were not tuned on, so the numbers mean something.
- As an **operator**, I want to accept a false positive by approving the tool, without switching the analyzer off for everyone.

## Acceptance criteria (EARS)

**Framework (FR-022)**
- **AC-1:** EACH finding SHALL carry: `analyzer`, `rule`, `severity` (`info`, `low`, `medium`, `high`), `channel` (`CH-1`…`CH-7`), `location` (a JSON Pointer, DESIGN.md §5.6), and `excerpt`. The excerpt is at most 120 characters, secret-redacted, and stored with every Cc/Cf/Zl/Zp code point escaped.
- **AC-2:** THE text extractor SHALL produce `(location, string)` pairs by walking **every string value and every object key** in the channel's object, at any depth, rather than an allowlist of fields (future-proof, like T-18). It skips only: numbers, booleans, `mimeType`, `resultType`, `ttlMs`, `cacheScope`, `requestState` (opaque), and `uri`/`uriTemplate` **schemes** (the rest of a URI is analyzed). The objects walked per channel (2026-07-28 schema names) are:
  - **CH-1:** each `Tool`
  - **CH-2:** the `server/discover` or `initialize` result
  - **CH-4:** `prompts/list` entries and the `prompts/get` result, including messages, `resource_link` items, and embedded resource `text`
  - **CH-5:** `resources/list` and template entries
  - **CH-6:** `InputRequiredResult.inputRequests`. **Tool definitions inside a sampling request** (`CreateMessageRequestParams.tools`) are analyzed as CH-1 objects. An elicitation `url` is analyzed and also gets an `elicitation.url` finding (severity `medium`), because URL-mode elicitation can be used for phishing.
  - **CH-7:** legacy server requests, the same as CH-6
- **AC-3** (T-02): EACH analyzer SHALL see each string twice: **raw**, and **normalized** (NFKC, then Unicode case folding, then removal of every Cf code point). A rule matches if it matches either form.
- **AC-4:** THE rules SHALL be data: one versioned YAML file embedded with `go:embed`, using Go's RE2 engine only (linear time; no backtracking constructs exist). Every rule SHALL list at least one positive and one negative example in the file, and a test SHALL run all of them.
- **AC-5:** Analysis results SHALL be cached by fingerprint (spec 003), so an unchanged tool or metadata is analyzed once per process. Strings longer than 64 KiB SHALL be analyzed up to 64 KiB, with an `analysis.truncated` finding (severity `low`).

**The four analyzers (DESIGN.md §5.4)**
- **AC-6 `unicode.hidden`:** (names: a `medium` finding only when the letters of a `name` come from more than one script, ignoring the `Common` and `Inherited` scripts, which hold digits, `_` and `-`. Single-script non-Latin names, for example localized ones, are not flagged.)
  - `high` for Unicode Tag characters (U+E0000–U+E007F) and bidi controls (U+202A–U+202E, U+2066–U+2069)
  - `medium` for other Cf code points (for example zero-width characters) and for Cc characters other than newline and tab
  - `medium` for a tool or server `name` mixing letters from more than one Unicode script (homoglyph names), as defined above
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
- **AC-13a (no third-party text in the repository; maintainer decision, decision 43):** THE corpus files below SHALL NOT be committed. A CI `corpus` job (network allowed in that job only) SHALL download the pinned MCPTox files, verify their SHA-256 against `testdata/corpora/mcptox/source.json`, convert them into the git-ignored `testdata/corpora/.cache/`, verify the converted files' SHA-256 (also in `source.json`), and then run AC-18 and AC-19. `actions/cache` keyed by the pinned commit avoids repeated downloads. Only `source.json`, `licenses.json` (metadata, no license texts), `NOTICE`, and `baseline.json` are committed. A test SHALL fail if any `*.jsonl` is tracked under `testdata/corpora/`. The `corpus` job's report and job summary SHALL be aggregate-only (rates, counts, item IDs); finding excerpts are written only to the cache, because CI logs are public. IF the download fails on a cache miss, THEN the job SHALL fail with a distinct `corpus unavailable` error, never as a metric regression.
- **AC-14:** `tools/corpus mcptox` SHALL convert MCPTox at a **pinned commit** into these files (in the cache, per AC-13a):
  - **`testdata/corpora/mcptox/poisoned.jsonl`:** all 485 records of `pure_tool.json`, each with `id`, `server`, `tool_name`, `paradigm`, `risk`, `description`, and the source commit
  - **`testdata/corpora/mcptox/clean.jsonl`:** the clean, authentic tools named in `response_all.json` (`servers.<name>.tool_names`) **for the servers allowed by AC-14a only** (322 tools from 42 servers on the pinned data). Each record holds `server`, `server_url`, `license` (SPDX ID), `name`, `description`, and arguments (name, description, required), parsed from that server's clean tool listing. The parser SHALL match every one of the 353 names of all 45 servers exactly, de-duplicate repeated listings, and fail on a missing name, before filtering.
  - **`testdata/corpora/mcptox/tool_names.json`:** each of the 45 servers' tool names (identifiers only, no descriptions), used as cross-reference context (AC-15).

  A `NOTICE` file SHALL give the CC BY 4.0 attribution the license asks for: the MCPTox contributors; the paper citation (AAAI 2026, DOI 10.1609/aaai.v40i42.40895); the source repository URL and commit; a link to the license; and the changes made (format conversion and parsing; content unchanged). It SHALL also list, per included upstream server, its `server_url`, the upstream commit checked, the SPDX license ID, and its copyright line, (no license texts are needed, because no copies are distributed).
- **AC-14a (third-party licensing):** MCPTox's CC BY 4.0 grant covers only material its contributors hold rights to; the clean descriptions were copied from 45 third-party servers. `testdata/corpora/mcptox/licenses.json` SHALL record, for each server, `server_url`, the upstream repository and commit checked, the license file path, and the SPDX ID. Only servers whose repository has a license **file** naming MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, or ISC SHALL be included in `clean.jsonl`. A test SHALL fail if `clean.jsonl` contains a server not allowed by `licenses.json`. On the pinned data three servers are excluded:

  | Server | Tools | Reason |
  |---|---|---|
  | AdFin | 20 | No license file in the repository |
  | KeywordsPeopleUse | 4 | ISC is declared only in `package.json`; there is no license file or copyright notice to reproduce |
  | Prisma | 7 | Source is a documentation page, not a licensed repository |

  The poisoned descriptions are MCPTox's own work (CC BY 4.0), so all 485 stay. `corpus-provenance.yml` (AC-16a) SHALL also re-fetch each license file at its recorded commit and fail if its SPDX classification changes.
- **AC-15:** EACH corpus record SHALL be turned into analyzer input in a defined way:
  - **Clean tools:** a CH-1 `Tool` object, `{name, description, inputSchema}`, built from the parsed arguments.
  - **Poisoned items:** `{name: tool_name, description}`. MCPTox gives no schema for them, so **`schema.side_channel` is reported as "not measured" for detection.** Its false positives are still measured on the clean tools.
  - **Cross-reference context** for both corpora is the server's tool names from `tool_names.json`, including the three excluded servers.
- **AC-16:** THE conversion SHALL be lossless: a test SHALL show that decoding the converted files reproduces the source strings exactly. (The ASCII-escaping rule is withdrawn: the files are not tracked, so spec 002 AC-34 doesn't apply.)
- **AC-16a (availability, no maintainer step):** A weekly `corpus-provenance.yml` job SHALL run the AC-13a download and checks without the cache, and re-check each `licenses.json` entry's SPDX classification, so a vanished or changed upstream is noticed before a PR needs it.
- **AC-16b:** THE repository's `gitleaks` configuration SHALL allowlist exactly the regex `AKIAEXAMPLECANARYL[A-H]Z` (spec 007) and nothing else. The corpus path needs no exemption, because the corpus isn't committed (AC-13a).
- **AC-17:** THE split SHALL be **by server**: held-out = `sha256(server)[0] & 1 == 1`, the low bit of the **first** byte of the SHA-256 digest of the UTF-8 server name. Both corpora use the same function, so a held-out server's poisoned and clean tools are both held out. On the pinned data this holds out 20 of 45 servers (178 poisoned and 156 clean tools; all three paradigms present; one excluded server, KeywordsPeopleUse, is in the held-out half). Rules are written and tuned against the tuning half only, as stated in CONTRIBUTING.md. A test fixes the split.
- **AC-18:** CI SHALL report, on the **held-out** halves, each with a **Wilson 95 % interval**:
  - **detection rate:** poisoned items with at least one finding of severity ≥ `medium`
  - **hide rate:** poisoned items with at least one `high` finding
  - **false-positive rates:** clean tools with a finding ≥ `medium`, and with a `high` finding

  Results are broken down per analyzer (`not measured` where AC-15 says so), per MCPTox paradigm, and per risk category, in the job summary and in `testdata/corpora/report.json`.
- **AC-19:** CI SHALL fail IF any held-out **point value** is worse than in `testdata/corpora/baseline.json`. The analysis is deterministic, so any lost detection or new false positive is a real change, not noise; the intervals are for interpretation. **A PR that changes `baseline.json` SHALL contain a line `baseline-change: <reason>` in its body or a commit message, which the `meta` job checks.** The IDEA.md targets (≥ 90 % detection, ≤ 2 % false positives) are shown in the README next to the current values and intervals. **They are goals, not gates.**

**Suite (spec 001 expectations become required)**
- **AC-20 (frozen payloads, no circularity):** THE lab payload strings SHALL live in `lab/servers/*/payload.txt` files, which are written by spec 001 and based on a cited public example (spec 001 AC-8). A `meta` check SHALL fail any PR that changes both a `payload.txt` file and `internal/analyzers/rules.yaml`. Payloads are never adjusted to fit the rules, and rules are never written against a payload.
- **AC-21:** THE following runs SHALL drop `pending: spec-004`, each with setup `{approve: all, approve_metadata: true}`:

  | Scenario | Control | `warn` | `enforce` |
  |---|---|---|---|
  | L-01 | `analyzer:text.imperative/*` | attack observables true; control fired | `poison_delivered: false` |
  | L-03 | `analyzer:text.cross_reference/*` | as above | `poison_delivered: false` |
  | L-05 | `analyzer:schema.side_channel/*` | as above | `poison_delivered: false`, `canary_exfiltrated: false` (the poisoned tool itself is hidden, so the call gets `-32602`) |
  | L-06 | `analyzer:unicode.hidden/*` | as above | `poison_delivered: false` |
  | L-07 | `analyzer:text.imperative/*` | as above | `poison_delivered: false` |

  IF the analyzers do not detect a frozen payload at `high` severity, THEN that run SHALL be marked `known_gap: "<reason>"` instead of being tuned. The suite reports known gaps separately, and the README lists them. For L-01, L-03, and L-07 in `enforce`, `canary_exfiltrated` and `forbidden_call_executed` are **not asserted**. The scripted replay still calls the *clean* tools. That the poison never reaches the model is the property an analyzer provides, and the README says so; spec 006's policy runs assert the call-level blocks.
- **AC-21a:** THE README results table SHALL show these cells, any known gaps, and the analyzer metrics with intervals and targets.

**Performance**
- **AC-22** (NFR-004): THE spec 002 benchmark SHALL run with all four analyzers enabled and caching on, and the p95 < 5 ms gate SHALL still pass. A separate benchmark SHALL report cold (uncached) analysis time per tool definition, which is reported but not gated.

## Out of scope
The ML classifier (v0.3); detecting injection in tool **results** (AR-9, v0.3); blocking on prompts or resources (v0.2); the `tools` CLI that shows findings (spec 005).

## Open questions
None.
