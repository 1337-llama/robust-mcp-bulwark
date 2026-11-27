# Plan 005: `tools` CLI

## Approach
`cmd/bulwark` gains a `tools` command group on top of `internal/registry`. A new `internal/registry/observed.go` gives the gateway a write path for observations that is separate from the pins file. The CLI reads both files, computes states and diffs, and writes only the pins file, through the same store API (atomic save and lock) that spec 003 defined. Every printed server string goes through `internal/termsafe`.

## Modules and files
| Path | New/Changed | Responsibility |
|---|---|---|
| `internal/registry/observed.go` | New | Observation file (AC-1, AC-3): atomic, locked, bounded |
| `internal/pipeline/pin_interceptors.go` | Changed | Write observations instead of touching the pins file in `warn`/`enforce` (AC-2) |
| `internal/registry/state.go` | New | Computes per-item state from pins + observations (AC-4) |
| `internal/diff/` | New | Structural JSON diff with JSON Pointer paths; line diff for long strings |
| `cmd/bulwark/tools.go` | New | `list`, `diff`, `approve`, `reject`, flags, exit codes, `--json` |
| `internal/audit/cli.go` | New | Per-server CLI audit chain, appended under the lock (AC-14) |
| `lab/suite/setup.go` | Changed | Observation pass (analyzers off), then `tools approve --fingerprint` per `setup` (AC-18) |
| DESIGN.md §6.1, §6.4 | Changed | CLI flags; observation file next to the pins file |

## Interfaces and data structures
```
bulwark tools list    --server-id ID [--json]                                   exit 0 | 3
bulwark tools diff    --server-id ID [TOOL | --metadata]
bulwark tools approve --server-id ID (TOOL | --metadata) [--fingerprint sha256:…]
bulwark tools approve --server-id ID --all --fingerprints FILE
bulwark tools reject  --server-id ID (TOOL | --metadata)
```

**Observation file** (`<server_id>.observed.json`):
```json
{
  "schema_version": 1,
  "server_id": "fs",
  "command": {"digest": "sha256:…", "argv": ["npx", "-y", "@modelcontextprotocol/server-filesystem@<exact-version>", "/workspace"], "executable": "/usr/bin/npx", "executable_sha256": "…"},
  "metadata": {"fingerprint": "sha256:…", "snapshot": {}, "first_seen": "…", "findings": []},
  "tools": {"read_file": {"fingerprint": "sha256:…", "snapshot": {}, "first_seen": "…", "findings": []}},
  "duplicates": ["send_email"],
  "limit_exceeded": false
}
```

**State computation:** the first matching row wins, so overlapping cases have one answer (`duplicate` > `rejected` > `not-seen` > `changed` > `pending` > `approved`). The table test enumerates every pin × observation combination.
| # | Pin | Observed | State |
|---|---|---|---|
| 1 | any | name in `duplicates` | `duplicate` |
| 2 | `rejected` | any | `rejected` |
| 3 | any | absent | `not-seen` |
| 4 | `approved` | present; store `command_digest` ≠ observed `command.digest` | `changed` (reason `command`) |
| 5 | `approved`, other fingerprint | present | `changed` (reason `fingerprint`) |
| 6 | none or `pending` | present | `pending` |
| 7 | `approved`, same fingerprint | present | `approved` |

The command row of `tools list` is `approved` when the digests match and `changed` otherwise.

**Approval transaction:**
1. Take the lock.
2. Reload both files.
3. Recompute the fingerprint of the observed snapshot with the pin's `exclude_fields`; require recomputed = observed = `--fingerprint` (for `--command`, observed digest = `--fingerprint`).
4. Write the pin: snapshot, fingerprint, `findings_at_approval` = current findings, `approved_at` (for `--command`, only the store's `command_digest`).
5. Atomic save.
6. Release the lock.
7. Append the CLI audit record.

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1–AC-3 | Unit and integration: the observation file is written in `warn`/`enforce`; pins-file bytes are unchanged; a second listing without a tool drops it and keeps `first_seen` for the rest; an unchanged listing causes no write; 1,001 tools → bounded with `limit_exceeded`, then a 3-tool listing records all 3 | `internal/registry/observed_test.go`, `internal/proxy/observe_test.go` |
| AC-4, AC-5 | Exhaustive table test of the state rows and their precedence; golden `list` output (text and JSON) for every state, including the command row; exit codes | `cmd/bulwark/tools_list_test.go` |
| AC-6–AC-8 | Golden diffs (field change, new property, removed annotation, long description, roles beside properties, `roles.unknown_param`) and the hostile-string golden test | `internal/diff/diff_test.go`, `cmd/bulwark/tools_diff_test.go` |
| AC-9–AC-13 | Approve with a matching or stale `--fingerprint`; a snapshot edited on disk so it no longer matches its stored fingerprint → refused; `--command` approval leaves tool pins untouched, and a tool approval leaves `command_digest` untouched; interactive confirmation through a pseudo-terminal on `/dev/tty` (`github.com/creack/pty`, MIT, test-only), and piped stdin can't confirm; non-interactive refusal; the `--all` guard rails (never includes the command); reject; metadata | `cmd/bulwark/tools_approve_test.go` |
| AC-14 | The CLI audit chain verifies with `audit verify`, including after two concurrent CLI invocations | `internal/audit/cli_test.go` |
| AC-15 | Integration: gateway running in `enforce`, the CLI approves, the client's next `tools/list` includes the tool within about 1 s; with a listen stream, the client gets `list_changed` | `internal/proxy/approve_live_test.go` |
| AC-16, AC-17 | Permission refusal; network check (no `net` imports, and the CLI runs under the suite's syscall trace) | `cmd/bulwark/tools_perm_test.go`, `tools/meta` |
| AC-18 | The suite passes with setup through the CLI approval path; every seeded pin has empty `findings_at_approval`; the runner never writes the pins file; every `policy:` run's decision input carries its `setup.arg_roles` | `lab/suite/setup_test.go` |

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| The observation file grows without bound, or a hostile server fills it once to lock out real tools | Each listing replaces the set, with per-listing caps (AC-1, AC-3) |
| An operator approves blindly with `--all` | Requires a fingerprints file, and approves only items that still match it (AC-11) |
| A pseudo-terminal test library adds a dependency | Test-only, MIT, pinned; production code has no dependency on it |
