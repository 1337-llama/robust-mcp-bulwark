# Spec 005: `tools` CLI (list, diff, approve, reject)

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-027 (`tools` commands), FR-029 (terminal-safe output); threats T-08, T-11; spec 003 AC-4, AC-7, AC-8, AC-14, AC-14a |
| Milestone | M2 |
| Depends on | Spec 002 (CLI, `termsafe`, audit), spec 003 (pin store, findings hook), spec 004 (findings) |

## Summary
This is the operator's side of pinning: `bulwark tools list | diff | approve | reject`.
- **What the operator sees:** the CLI shows what the server **currently offers** compared with what was **approved**, along with the analyzer findings.
- **What it records:** approvals record the reviewed fingerprint and the current findings. That is how an operator accepts a false positive (spec 003 AC-14).
- **How it stays safe:** every byte of server-supplied text is printed through `termsafe`. An approval made by fingerprint can't be swapped for something the operator didn't review.

**Design addition (observation file):** the gateway records what it **observed** (definitions, fingerprints, findings) in a separate file per server. **The pins file stays writable only by `learn` mode and the CLI** (spec 003 AC-7), and server-supplied data never lands in it except through an explicit approval.

## User stories
- As a **developer**, after a rug pull is quarantined, I want to see exactly what changed and approve or reject it in one command.
- As a **security reviewer**, I want an approval to cover exactly the version I looked at, even if the server changes again in the meantime.
- As an **IR analyst**, I want every approval and rejection in the audit log.

## Acceptance criteria (EARS)

**Observation file**
- **AC-1:** THE gateway SHALL write, atomically and under the spec 003 lock discipline, `<state_dir>/pins/<server_id>.observed.json` (`schema_version: 1`). It holds:
  - the observed `command`: `digest` (spec 003 AC-4), `argv`, executable path, and executable SHA-256
  - for each tool and for the metadata: the latest `fingerprint`, `snapshot` (as received), `first_seen`, and current `findings`
  - each name listed more than once

  Each **complete** `tools/list` result (all pages) SHALL **replace** the tool set, keeping `first_seen` for names that persist, so names no longer served drop out. THE gateway SHALL write the file only when its content changes.
- **AC-2:** THE gateway SHALL NEVER write `<server_id>.json` (the pins file) outside `learn` mode. Only the CLI and `learn` write it. A test SHALL drive `warn`/`enforce` traffic and assert the pins file's bytes are unchanged.
- **AC-3:** EACH listing written to the observation file SHALL be bounded: at most 1,000 tools and 16 MiB. IF a listing exceeds either, THEN THE gateway SHALL record that listing's first entries in listing order, set `limit_exceeded`, and treat unrecorded tools as unapproved. Because the next listing replaces the set (AC-1), an oversized listing can't lock out tools permanently.

**`tools list`**
- **AC-4:** `bulwark tools list --server-id ID` SHALL print one row for the command, one per tool, and one for the metadata: name, state (`approved`, `pending`, `changed`, `rejected`, `duplicate`, `not-seen`), the approved and observed fingerprints (first 12 hex digits each), and the count and maximum severity of current findings. A `changed` state SHALL name its reason: `fingerprint`, or `command` while the observed command digest is unapproved. Where several states apply, precedence is `duplicate` > `rejected` > `not-seen` > `changed` > `pending` > `approved`. `--json` SHALL print the same data as JSON.
- **AC-5:** THE exit code of `tools list` SHALL be 0 if everything observed is approved and unchanged, and 3 if anything needs review. Scripts and CI can then use it as a check.

**`tools diff`**
- **AC-6:** `bulwark tools diff --server-id ID [TOOL | --metadata]` SHALL show, for each item that isn't approved and unchanged, a structural diff between the approved snapshot and the observed one (JSON-Pointer paths, with added, removed, and changed values). Long string changes (over 80 characters) are shown as a line diff. Current findings are listed with their locations. For a tool, the diff SHALL also list each `inputSchema` property with its configured role, or `no role`, so a decoy (a role left on a renamed or newly unused parameter) is visible. A configured role naming a property that is absent from `inputSchema` SHALL be shown as a `roles.unknown_param` warning in `diff` and counted with the findings in `list`.
- **AC-7** (FR-029, T-11): EVERY server-supplied string printed by any `tools` command SHALL pass through `termsafe`. Golden tests SHALL include a tool whose description contains an ANSI clear-screen sequence, an OSC 8 hyperlink, an RLO, and the L-06 Tag payload. None of them may reach the output raw.
- **AC-8:** THE diff SHALL end with the exact command that approves what was shown, including `--fingerprint`.

**`tools approve` / `tools reject`**
- **AC-9:** `bulwark tools approve --server-id ID TOOL --fingerprint sha256:<hex>` SHALL copy the observed snapshot, fingerprint, and current findings into the pin, as `findings_at_approval`, and set `status: approved` with `approved_at`. Under the lock, it SHALL **recompute** the fingerprint from the observed snapshot with the pin's `exclude_fields`. IF the recomputed value, the stored observed fingerprint, and `--fingerprint` are not all equal, THEN it SHALL refuse with exit code 3 and change nothing. This protects against time-of-check to time-of-use races, a stale or corrupt observation file, and an `exclude_fields` mismatch. A tool approval SHALL NOT change the store's `command_digest`.
- **AC-9a** (spec 003 AC-4): `bulwark tools approve --server-id ID --command --fingerprint sha256:<digest>` SHALL set the store's `command_digest` to the observed digest, with the same refusal rule. `tools diff --command` SHALL show the old digest and the observed argv, executable path, and hash. Until the command is approved, every item stays `changed` (reason `command`); once it is, each tool and the metadata is judged on its own fingerprint, so only items that really changed need review.
- **AC-10:** Without `--fingerprint`, `approve` SHALL work only when stdin is a terminal. It shows the diff (AC-6) and asks for confirmation by typing the first 8 hex digits of the fingerprint, read from `/dev/tty`, not from stdin, so piped input can't answer the prompt. In a non-interactive context without `--fingerprint`, it SHALL refuse with exit code 2.
- **AC-11:** `--all` SHALL approve every pending or changed item, but only together with a `--fingerprints FILE` listing name → fingerprint (as produced by `tools list --json`), and only items whose observed fingerprint matches the file. This SHALL NOT be possible from a bare `--all`.
- **AC-12:** `bulwark tools reject --server-id ID TOOL` SHALL set `status: rejected`. A rejected tool is hidden in `enforce` (spec 003). `learn` never re-approves it (spec 003 AC-9), and only a later explicit `approve` can.
- **AC-13:** `--metadata` SHALL apply `approve` and `reject` to the server metadata, with the same fingerprint rules. `--all` (AC-11) SHALL NOT include the command; it is always approved on its own.
- **AC-14:** EVERY approval and rejection SHALL write an audit record (`pin_event`, with the action, item, old and new fingerprint, and the number of findings accepted) to one CLI hash chain per server, `audit/<server_id>/cli.jsonl`, appended under the pin-store lock, so `audit verify` covers it.
- **AC-15:** A change written by the CLI SHALL be picked up by a running gateway within about one second (spec 003 AC-16a event tier). IF a tool became visible, THEN the client is notified (spec 003 AC-14a). An integration test SHALL show approve → the next `tools/list` from the client includes the tool, with no gateway restart.

**Safety**
- **AC-16** (T-08): THE `tools` commands SHALL apply the same `state_dir` permission checks as `wrap` (spec 002 AC-29), and SHALL refuse to write if the pins file or its directory is group- or world-writable.
- **AC-17:** `tools` commands SHALL never contact the upstream server or the network. They read only the state files (NFR-014).

**Suite**
- **AC-18:** THE spec 001 run setup (AC-27) SHALL seed pins the way an operator does. It runs a preliminary **observation pass** (Bulwark in `warn` mode with `analyzers.enabled: []`, replay steps `discover` and `list_tools` only), which writes only the observation file (AC-1). Analyzers are off in this pass so that the approvals record **no** findings; otherwise `approve` would accept the very findings an analyzer run must catch (as spec 004 AC-12 ensures for `learn`). A suite test SHALL assert that every seeded pin has an empty `findings_at_approval`. It then runs `bulwark tools approve --fingerprint` for each item that `setup` approves. Items not approved stay unpinned (`pin:unapproved`). The runner SHALL NOT write the pins file itself, so the suite exercises the same approval path operators use. A run's `setup.arg_roles` go into its generated configuration (decision 39). A suite test SHALL assert that, for every `policy:` run, the policy decision input carries those roles.

## Out of scope
Editing `exclude_fields` or `arg_roles` from the CLI. `exclude_fields` is edited in the pins file by hand; `arg_roles` live only in the configuration (decision 39). A TUI. Remote or multi-host pin management.

## Open questions
None.
