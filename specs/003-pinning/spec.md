# Spec 003: Fingerprints, pin store, modes, verify-before-call, server metadata

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-021, FR-030, FR-033 (also FR-024's role-mapping storage); threats T-06, T-08, T-18; mitigations M-2, M-8 |
| Milestone | M2 |
| Depends on | Spec 002 (pipeline, canonical form, gateway-originated requests, audit) |

## Summary
This is Bulwark's first real security control. Every tool definition and the server's metadata (`instructions` and server info) are **fingerprinted**, and the fingerprints are pinned per server. In `enforce` mode:
- a new or changed tool is **hidden**, and calls to it get "Unknown tool"
- new or changed metadata has its `instructions` and free-text fields **stripped**

This lasts until an operator approves it. Before a call, Bulwark **re-checks** a tool whose view is stale, so a silent definition change (a rug pull) is noticed even when the client never re-lists.

Two spec 001 attack tests become real: **L-02** (rug pull, `pin:changed`) and **L-07** (poisoned server instructions, `pin:unapproved`).

## User stories
- As a **developer**, I want a tool that changes after I approved it to disappear until I look at it again, so a trusted server can't quietly turn malicious.
- As a **security reviewer**, I want every field of a tool to count, so an attacker can't hide changes in fields that aren't hashed.
- As an **operator**, I want server `instructions` treated like tool descriptions, since they reach the model the same way.

## Acceptance criteria (EARS)

**Fingerprints (FR-021, FR-033, T-18)**
- **AC-1:** THE gateway SHALL fingerprint each tool as `sha256:<hex>` of the canonical form (`internal/canon`, DESIGN.md §5.3) of the **whole tool object as received**, including `annotations`, `icons`, `_meta`, and unknown fields. Only fields named in that tool's `exclude_fields` in the pin store are left out; that list is empty by default.
- **AC-2:** THE gateway SHALL fingerprint the server metadata as the canonical form of `{instructions, serverInfo, capabilities}`. `serverInfo` comes from the result's `_meta["io.modelcontextprotocol/serverInfo"]` under 2026-07-28, and from `serverInfo` under 2025-11-25. A missing member is fingerprinted as absent, not as `null`.
- **AC-3:** WHEN a tool's `exclude_fields` changes, THE gateway SHALL record a `pin_event` audit record naming the old and new lists.

**Server identity (DESIGN.md §5.3)**
- **AC-4:** THE pin store SHALL record the `command_digest`. IF the current digest differs, THEN every tool and the metadata SHALL be treated as `changed` (control `pin:changed`) until re-approved.
- **AC-5:** WHEN `bulwark wrap` starts, IF an `npx` or `uvx` package argument has no exact version, or a `docker run` image has no `@sha256:` digest, THEN THE gateway SHALL print an `identity.unpinned_package` warning to stderr and record it.

**Pin store (DESIGN.md §6.4)**
- **AC-6:** THE pin store SHALL be one JSON file per server at `<state_dir>/pins/<server_id>.json` (`schema_version: 1`, the §6.4 fields), written atomically (temporary file + rename), with mode `0600`, under an advisory file lock. A test with concurrent writers SHALL show no lost or corrupted updates.
- **AC-7:** A pin's `status` (`pending`, `approved`, `rejected`) SHALL change only by: (a) `learn` mode, which approves new or changed items; or (b) the operator CLI (spec 005). **No MCP message SHALL ever change a pin's status in `warn` or `enforce` mode.**
- **AC-8** (FR-024): THE pin store SHALL store each tool's `arg_roles` from the configuration. WHEN they change, THE gateway SHALL record a `pin_event` audit record.

**Modes (FR-021)**
- **AC-9:** WHILE in `learn` mode, THE gateway SHALL pin new and changed tools and metadata as `approved`, and record a `pin_event`.
- **AC-10:** WHILE in `warn` mode, THE gateway SHALL forward everything. For each unapproved, changed, or rejected item it SHALL record a finding (`pin.unapproved` or `pin.changed`) and list the control (`pin:unapproved` or `pin:changed`) in the audit record's `controls`.
- **AC-11:** WHILE in `enforce` mode, THE gateway SHALL remove unapproved, changed, and rejected tools from every `tools/list` result page, keeping `nextCursor` and every other field unchanged.
- **AC-12:** WHILE in `enforce` mode, WHEN a `tools/call` names a tool that is hidden, unapproved, changed, rejected, or unknown to the pin store, THE gateway SHALL NOT forward it, and SHALL answer with JSON-RPC error `-32602` and message `Unknown tool: <name>` (DESIGN.md §6.6).
- **AC-13** (FR-033): WHILE in `enforce` mode, WHEN the server metadata is unapproved or changed, THE gateway SHALL remove `instructions`, and SHALL remove every `serverInfo` member except `name` and `version` (that is, `title`, `description`, `websiteUrl`, `icons`, and any unknown members) before forwarding. `capabilities` is forwarded unchanged, but it is part of the fingerprint.
- **AC-14 (analyzer hook):** THE registry SHALL accept findings from analyzers (spec 004). WHILE in `enforce` mode, a tool or metadata with a **high**-severity finding SHALL be handled as unapproved (hidden or stripped) even if its pin is `approved`. Spec 003 tests this with a stub analyzer.

**Bulwark's own `server/discover` (DESIGN.md §5.2)**
- **AC-15:** UNDER 2026-07-28, IF the client's first modern request is not `server/discover`, THEN THE gateway SHALL send its own `server/discover` first, using a gateway-originated ID (spec 002 AC-13), and apply AC-2, AC-13, and AC-14 to the result **before** forwarding the client's request. This happens at most once per process. Under 2025-11-25, the `initialize` result is used.

**Verify-before-call (FR-030, M-2)**
- **AC-16:** THE gateway SHALL mark its view of the tool list **stale** WHEN any of these happens:
  - a `notifications/tools/list_changed` arrives (spec 002 AC-33 guarantees it is processed)
  - the view's age exceeds `min(ttlMs, pin_recheck_max_age)`; a `ttlMs` of 0 is ignored
  - the pin store changes on disk (`mtime` checked before each call)
- **AC-17:** WHILE in `enforce` mode, WHEN a `tools/call` arrives and the view is stale, THE gateway SHALL fetch `tools/list` itself, following every `nextCursor`, before deciding. These re-checks SHALL happen at most once per `pin_recheck_min_age` (default 30 s). IF the called tool's fingerprint no longer matches its approved pin, THEN the call SHALL be blocked as in AC-12, with finding `pin.changed`.
- **AC-18:** THE gateway SHALL record each `tools/list` result's `ttlMs` and `cacheScope` in its audit record.

**Suite (spec 001 expectations become required)**
- **AC-19:** THE manifests SHALL drop `pending: spec-003` from these runs, and their expectations SHALL pass:
  - **L-02**, control `pin:changed`, setup `approve: all` taken before the change:
    - `warn`: `canary_exfiltrated: true`, `controls_fired: [pin:changed]`
    - `enforce`: `poison_delivered: false`, `canary_exfiltrated: false`, `controls_fired: [pin:changed]`
  - **L-07**, control `pin:unapproved`, setup `approve_metadata: false`:
    - `warn`: `poison_delivered: true`, `controls_fired: [pin:unapproved]`
    - `enforce`: `poison_delivered: false`, `controls_fired: [pin:unapproved]`

    `canary_exfiltrated` is **not asserted** for L-07. The replay calls the clean `search` tool with the canary regardless, as a scripted agent always would, and a clean tool call is outside what metadata pinning controls. The README states this.
- **AC-20:** THE README results table SHALL show L-02 and L-07 as blocked under `enforce`, with the control that fired.

**Performance**
- **AC-21** (NFR-004): THE spec 002 benchmark SHALL include the pinning interceptors, and the p95 < 5 ms gate SHALL still pass. Gateway-originated re-checks are excluded, because they include upstream time.

## Out of scope
The `tools` CLI for listing, diffing, approving, and rejecting (spec 005; this spec's tests set statuses through the store API). Analyzers (spec 004; the hook in AC-14 is stubbed). Pinning and blocking prompts and resources (v0.2, AR-8).

## Open questions
None.
