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
- **AC-1a:** IF a tool name appears more than once in one listing (on one page or across pages), THEN THE gateway SHALL record a `pin.duplicate_name` finding (control `pin:duplicate_name`). In `enforce` mode it SHALL hide **every** object with that name and treat calls to it as in AC-12.
- **AC-2** (T-18): THE gateway SHALL fingerprint the server metadata as the canonical form of the **whole** `server/discover` result (2026-07-28) or `initialize` result (2025-11-25), **minus the volatile members** `ttlMs`, `cacheScope`, and `resultType`. This includes `instructions`, `serverInfo` (from the result's `_meta["io.modelcontextprotocol/serverInfo"]` under 2026-07-28), `capabilities`, `supportedVersions` or `protocolVersion`, all other `_meta` keys, and unknown members. A missing member is fingerprinted as absent, not as `null`.
- **AC-3:** WHEN a tool's `exclude_fields` changes, THE gateway SHALL record a `pin_event` audit record naming the old and new lists.

**Server identity (DESIGN.md §5.3)**
- **AC-4:** THE pin store SHALL record the `command_digest`. IF the current digest differs, THEN every tool and the metadata SHALL be treated as `changed` (control `pin:changed`) until re-approved.
- **AC-5:** WHEN `bulwark wrap` starts, THE gateway SHALL print an `identity.unpinned_package` warning to stderr, and record it, IF any of these is true:
  - an `npx` package argument is not an exact version: `name@x.y.z`, with an optional pre-release suffix. Ranges (`@^1`, `@1.x`), dist-tags (`@latest`, `@next`), and a missing version all count as unpinned.
  - a `uvx` package isn't pinned with `==x.y.z`
  - a `docker run` image has no `@sha256:` digest

**Pin store (DESIGN.md §6.4)**
- **AC-6:** THE pin store SHALL be one JSON file per server at `<state_dir>/pins/<server_id>.json` (`schema_version: 1`, the §6.4 fields), written atomically (temporary file + rename), with mode `0600`, under an advisory file lock. A test with concurrent writers SHALL show no lost or corrupted updates.
- **AC-7:** A pin's `status` (`pending`, `approved`, `rejected`) SHALL change only by: (a) `learn` mode, which approves new or changed items; or (b) the operator CLI (spec 005). **No MCP message SHALL ever change a pin's status in `warn` or `enforce` mode.**
- **AC-8** (FR-024): THE pin store SHALL store each tool's `arg_roles` from the configuration. WHEN they change, THE gateway SHALL record a `pin_event` audit record.

**Modes (FR-021)**
- **AC-9:** THE gateway SHALL decide every tool and the metadata with the **total** decision table in plan.md, which covers every combination of mode (`learn`, `warn`, `enforce`) and pin state: missing; pending; approved and unchanged; approved and changed; rejected; rejected and changed. An exhaustive table test SHALL enforce this. In particular:
  - `learn` pins **missing**, **pending**, and **approved-but-changed** items as `approved`, and records a `pin_event`.
  - `learn` SHALL NEVER change a **rejected** pin: the item stays rejected, is forwarded with a `pin.rejected` finding, and the event is audited.
- **AC-10:** WHILE in `warn` mode, THE gateway SHALL forward everything. For each item that isn't approved and unchanged, it SHALL record a finding (`pin.unapproved`, `pin.changed`, or `pin.rejected`) and list the matching control (`pin:unapproved` or `pin:changed`; rejected items use `pin:unapproved`) in the audit record's `controls`.
- **AC-11:** WHILE in `enforce` mode, THE gateway SHALL remove unapproved, changed, rejected, and duplicate-name tools from every `tools/list` result page, keeping `nextCursor` and every other field unchanged.
- **AC-12:** WHILE in `enforce` mode, WHEN a `tools/call` names a tool that is hidden, unapproved, changed, rejected, duplicated, or unknown to the pin store, THE gateway SHALL NOT forward it, and SHALL answer with JSON-RPC error `-32602` and message `Unknown tool: <name>` (DESIGN.md §6.6).
- **AC-13** (FR-033): WHILE in `enforce` mode, WHEN the server metadata is unapproved or changed, THE gateway SHALL forward a **reduced** result that keeps only:
  - `supportedVersions` or `protocolVersion`
  - `capabilities`
  - `ttlMs`, `cacheScope`, `resultType`
  - `serverInfo` reduced to `name` and `version`, each capped at 128 characters (longer values are truncated, with a `pin.metadata_truncated` finding)

  Everything else is removed: `instructions`, `title`, `description`, `websiteUrl`, `icons`, other `_meta` keys, and unknown members. Spec 004 adds analyzers for `name` and `version`.
- **AC-14 (analyzer hook):** THE registry SHALL accept findings from analyzers (spec 004). WHILE in `enforce` mode, a tool or metadata with a **high**-severity finding SHALL be hidden or stripped, **unless that same finding (same analyzer, rule, and location) is listed in the pin's `findings_at_approval`**. That is how an operator accepts a false positive by approving it (spec 005 records the current findings on approval). Approvals made by `learn` record no findings, because analyzers are off in learn passes, so a later high finding still hides the item. Spec 003 tests this with a stub analyzer.
- **AC-14a (N4):** WHEN the pin store changes in a way that makes a hidden tool visible, THE gateway SHALL send the client `notifications/tools/list_changed`. Under 2026-07-28 it is sent only if the client has an open `subscriptions/listen` stream with `toolsListChanged`, and is tagged with that stream's `io.modelcontextprotocol/subscriptionId`. This lets the client see the newly approved tool without a restart.

**Gateway-originated requests: `server/discover` and re-check `tools/list` (DESIGN.md §5.2, §5.3)**
- **AC-15:** UNDER 2026-07-28, IF the client's first modern request is not `server/discover`, THEN THE gateway SHALL send its own `server/discover` first, and apply AC-2, AC-13, and AC-14 to the result **before** forwarding the client's request. This happens at most once per process. Under 2025-11-25, the `initialize` result is used.
- **AC-15a:** UNDER 2026-07-28, every gateway-originated request SHALL carry `_meta` `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`, copied from the client request that triggered it, so the server doesn't answer `-32022`.
- **AC-15b:** Gateway-originated requests SHALL time out after `limits.gateway_request_timeout` (default 10 s). This is the only timeout Bulwark adds (spec 002 AC-7). WHILE in `enforce` mode:
  - IF Bulwark's own `server/discover` fails, errors, or times out, THEN the metadata SHALL be treated as unapproved and the gateway continues.
  - IF a re-check `tools/list` fails, errors, or times out, THEN the call that triggered it SHALL be blocked as in AC-12, with finding `pin.recheck_failed`.
- **AC-15c:** A gateway-originated `tools/list` SHALL follow `nextCursor` for at most 100 pages and 16 MiB in total. IF either cap is exceeded, THEN it SHALL fail as in AC-15b, with a `limit_exceeded` record.

**Verify-before-call (FR-030, M-2)**
- **AC-16:** THE gateway SHALL normalize every `ttlMs` before use. A value that is missing (always under 2025-11-25), zero or negative, not an integer, not finite, or above 2^31 SHALL count as **no hint**. Across the pages of one listing, the smallest valid value is used.
- **AC-16a:** THE gateway SHALL mark its tool view **stale** WHEN any of these happens:
  - a `notifications/tools/list_changed` arrives (spec 002 AC-33 guarantees it is processed)
  - the view's age exceeds `min(ttlMs, pin_recheck_max_age)`, or `pin_recheck_max_age` alone when there is no hint
  - the pin store's `(device, inode, size, mtime)` changes, in which case the store is reloaded under its lock
- **AC-17:** WHILE in `enforce` mode, WHEN a `tools/call` arrives and the view is stale, THE gateway SHALL fetch `tools/list` itself (AC-15a–c) before deciding. Re-checks are rate-limited:
  - **after a notification:** at most one re-check per second, with notifications coalesced
  - **otherwise:** at most one per `pin_recheck_min_age` (default 30 s)

  IF the called tool's fingerprint no longer matches its approved pin, THEN the call SHALL be blocked as in AC-12, with finding `pin.changed`.
- **AC-17a:** WHILE in `enforce` mode, IF the view is stale AND a re-check is not yet allowed by the rate limit, THEN THE call SHALL be blocked as in AC-12, with finding `pin.recheck_pending`, until a re-check succeeds. A server that floods notifications can therefore hurt only its own availability, never skip the check.
- **AC-18:** THE gateway SHALL record each `tools/list` result's raw `ttlMs` and `cacheScope` values, and the normalized hint, in its audit record.

**Suite (spec 001 expectations become required)**
- **AC-19:** THE manifests SHALL drop `pending: spec-003` from these runs, and their expectations SHALL pass:
  - **L-02**, control `pin:changed`, setup `{approve: all, approve_metadata: true}` taken before the change:
    - `warn`: `canary_exfiltrated: true`, `controls_fired: [pin:changed]`
    - `enforce`: `poison_delivered: false`, `canary_exfiltrated: false`, `controls_fired: [pin:changed]`
  - **L-07**, control `pin:unapproved`, setup `{approve: all, approve_metadata: false}`:
    - `warn`: `poison_delivered: true`, `controls_fired: [pin:unapproved]`
    - `enforce`: `poison_delivered: false`, `controls_fired: [pin:unapproved]`

    `canary_exfiltrated` is **not asserted** for L-07. The replay calls the clean `search` tool with the canary regardless, as a scripted agent always would, and a clean tool call is outside what metadata pinning controls. The README states this.
- **AC-20:** THE README results table SHALL show L-02 and L-07 as blocked under `enforce`, with the control that fired.

**Performance**
- **AC-21** (NFR-004): THE spec 002 benchmark SHALL include the pinning interceptors, and the p95 < 5 ms gate SHALL still pass. Gateway-originated re-checks are excluded, because they include upstream time.

**Spec 001 consistency (S5)**
- **AC-22:** THIS PR SHALL amend spec 001:
  - add `pin:duplicate_name`, `pin:recheck_pending`, and `pin:recheck_failed` to the control vocabulary (AC-2)
  - state the `setup` defaults in its plan: `approve: all`, `approve_metadata: true`. A run must say explicitly when it wants something unapproved.

## Out of scope
The `tools` CLI for listing, diffing, approving, and rejecting (spec 005; this spec's tests set statuses through the store API). Analyzers (spec 004; the hook in AC-14 is stubbed). Pinning and blocking prompts and resources (v0.2, AR-8).

## Open questions
None.
