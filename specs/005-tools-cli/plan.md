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
| `internal/audit/cli.go` | New | Per-invocation CLI audit chain (AC-14) |
| `lab/suite/setup.go` | Changed | Observation pass (analyzers off), then `tools approve --fingerprint` per `setup` (AC-18) |
| DESIGN.md §6.1, §6.4 | Changed | CLI flags; observation file next to the pins file |

## Interfaces and data structures
```
bulwark tools list    --server-id ID [--json]                                   exit 0 | 3
bulwark tools diff    --server-id ID [TOOL | --metadata]
bulwark tools approve --server-id ID (TOOL | --metadata) [--fingerprint sha256:…]
bulwark tools approve --server-id ID --all --yes-i-reviewed --fingerprints FILE
bulwark tools reject  --server-id ID (TOOL | --metadata)
```

**Observation file** (`<server_id>.observed.json`):
```json
{
  "schema_version": 1,
  "server_id": "fs",
  "metadata": {"fingerprint": "sha256:…", "snapshot": {}, "first_seen": "…", "last_seen": "…", "findings": []},
  "tools": {"read_file": {"fingerprint": "sha256:…", "snapshot": {}, "first_seen": "…", "last_seen": "…", "findings": []}},
  "duplicates": ["send_email"]
}
```

**State computation:**
| Pin | Observed | State |
|---|---|---|
| none | present | `pending` |
| `pending` | any | `pending` |
| `approved`, same fingerprint | present | `approved` |
| `approved`, other fingerprint | present | `changed` |
| `rejected` | any | `rejected` |
| any | name in `duplicates` | `duplicate` |
| any | absent | `not-seen` |

**Approval transaction:**
1. Take the lock.
2. Reload both files.
3. Compare the observed fingerprint with `--fingerprint`.
4. Write the pin: snapshot, fingerprint, `findings_at_approval` = current findings, `approved_at`.
5. Atomic save.
6. Release the lock.
7. Append the CLI audit record.

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1–AC-3 | Unit and integration: the observation file is written in `warn`/`enforce`; pins-file bytes are unchanged; 1,001 tools → bounded with `limit_exceeded` | `internal/registry/observed_test.go`, `internal/proxy/observe_test.go` |
| AC-4, AC-5 | Golden `list` output (text and JSON) for every state in the table; exit codes | `cmd/bulwark/tools_list_test.go` |
| AC-6–AC-8 | Golden diffs (field change, new property, removed annotation, long description) and the hostile-string golden test | `internal/diff/diff_test.go`, `cmd/bulwark/tools_diff_test.go` |
| AC-9–AC-13 | Approve with a matching or stale `--fingerprint`; interactive confirmation through a pseudo-terminal (`github.com/creack/pty`, MIT, test-only); non-interactive refusal; the `--all` guard rails; reject; metadata | `cmd/bulwark/tools_approve_test.go` |
| AC-14 | The CLI audit chain verifies with `audit verify` | `internal/audit/cli_test.go` |
| AC-15 | Integration: gateway running in `enforce`, the CLI approves, the client's next `tools/list` includes the tool within about 1 s; with a listen stream, the client gets `list_changed` | `internal/proxy/approve_live_test.go` |
| AC-16, AC-17 | Permission refusal; network check (no `net` imports, and the CLI runs under the suite's syscall trace) | `cmd/bulwark/tools_perm_test.go`, `tools/meta` |
| AC-18 | The suite passes with setup through the CLI approval path; every seeded pin has empty `findings_at_approval`; the runner never writes the pins file | `lab/suite/setup_test.go` |

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| The observation file grows without bound under a hostile server | Caps (AC-3) |
| An operator approves blindly with `--all` | Requires `--yes-i-reviewed` and a fingerprints file (AC-11) |
| A pseudo-terminal test library adds a dependency | Test-only, MIT, pinned; production code has no dependency on it |
