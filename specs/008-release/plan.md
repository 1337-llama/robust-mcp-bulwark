# Plan 008: One-command demo and release pipeline

## Approach
This spec adds almost no code: the demo reuses the suite runner (spec 001) and `tools diff` (spec 005), and the release is configuration for GoReleaser, Syft, cosign, and GitHub's attestation action. All of them are free tools that run on standard GitHub-hosted runners ($0, C-4). The release flow follows DESIGN.md §11 step by step.

## Modules and files
| Path | New/Changed | Responsibility |
|---|---|---|
| `cmd/bulwark-lab` `demo` subcommand, `lab/demo/demo.sh`, `Makefile` (`demo` target) | New | AC-1, AC-2: run the suite in `none` + `enforce`, print the table, show the L-02 diff |
| `tools/ci-summary` | Changed | `--compare results.json`: the demo table equals the suite cells (AC-3) |
| `.goreleaser.yaml` | New | Two archives (user, demo), reproducible flags, SBOMs (AC-4–AC-6) |
| `.github/workflows/release.yml` | New | Tag → build, sign, attest, reproducibility job, `govulncheck`, quickstart job (AC-5–AC-8, AC-11) |
| `.github/workflows/ci.yml` | Changed | Snapshot build and archive checks; `govulncheck`, dependency review, gitleaks (AC-9, AC-10) |
| `README.md` | Changed | "Try it in 10 minutes", the install commands in a fenced block that the quickstart job extracts (AC-8, AC-12) |

## Test approach
| Acceptance criterion | Test type | Location |
|---|---|---|
| AC-1–AC-4 | CI on every PR against snapshot archives: demo output vs `results.json`; archive listings | `ci.yml` job `demo` |
| AC-5–AC-8, AC-11 | The release workflow itself; first exercised on a pre-release tag (`v0.1.0-rc.1`) | `release.yml` |
| AC-7 | Two independent builds of the tag; checksums compared | `release.yml` job `reproducible` |
| AC-9, AC-10 | `ci.yml` on every PR | `ci.yml` |
| AC-12 | The quickstart job runs the README's own commands | `release.yml` job `quickstart` |

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| The README's commands drift from what works | They are extracted and run by the quickstart job (AC-8) |
| Builds aren't byte-reproducible (for example embedded paths or timestamps) | `-trimpath`, fixed `ldflags`, `SOURCE_DATE_EPOCH`, and `CGO_ENABLED=0`; the AC-7 job catches regressions |
| A signing step needs secrets | Keyless signing uses the workflow's OIDC token (`id-token: write`); no stored keys |
