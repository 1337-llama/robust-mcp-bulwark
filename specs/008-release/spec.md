# Spec 008: One-command demo and release pipeline

| Field | Value |
|---|---|
| Status | Ready (on merge of this PR) |
| Traces to | FR-007, NFR-011, NFR-012, NFR-015; threat T-L2 |
| Milestone | M3 |
| Depends on | Specs 001–007 (the suite and every control the demo shows) |

## Summary
A reviewer should see Bulwark work in under 10 minutes with nothing but a download, or a clone and Go. This spec adds:
- **`demo.sh` / `make demo`:** runs all eight attacks with and without Bulwark and prints the results table, then shows a rug pull being caught.
- **Release pipeline:** a version tag builds signed archives with SBOMs and provenance. CI then downloads the demo archive it just built, verifies it, and runs it. The quickstart is therefore tested, never assumed.
- **Dependency hygiene in CI:** `govulncheck`, dependency review, and a secret scan.

## User stories
- As a **portfolio reviewer**, I want one command that shows attacks succeeding directly and blocked through Bulwark.
- As a **user**, I want to verify that a release binary was built by this repository's CI.
- As the **maintainer**, I want releases to need nothing from me except pushing a tag.

## Acceptance criteria (EARS)

**Demo (FR-007, NFR-011)**
- **AC-1:** `demo.sh` (in the demo archive) and `make demo` (from a clone) SHALL run L-01…L-08 under `none` and `enforce` through `bulwark-lab demo`, a subcommand that reuses `lab/suite` (no Go toolchain needed), and print the README results table to stdout, `[LAB]` and `LAB ONLY` notices included. They need no network and no Docker.
- **AC-2:** THE demo SHALL then run L-02 and print the `bulwark tools diff` of the quarantined tool, which is hero demo 2 (DESIGN.md §3.3).
- **AC-3:** THE demo's table SHALL equal the corresponding cells of the suite's `results.json` for the same commit. CI compares them.
- **AC-4** (T-L2): THE user archive SHALL contain only `bulwark`, `LICENSE`, and `README.md`. The demo archive holds `bulwark`, `bulwark-lab` (with the `demo` subcommand), the manifests, and `demo.sh`. A CI check lists both archives and fails otherwise.

**Release (NFR-012)**
- **AC-5:** WHEN a tag `vX.Y.Z` is pushed, `release.yml` SHALL build with GoReleaser (`-trimpath`, fixed `ldflags`, `SOURCE_DATE_EPOCH` from the commit) for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and windows/amd64 (built, not tested, NFR-010).
- **AC-6:** THE release SHALL include `checksums.txt`, one SPDX JSON SBOM per archive (Syft through GoReleaser), a keyless cosign signature bundle for `checksums.txt` (GitHub OIDC identity), and GitHub artifact attestations for every archive.
- **AC-7:** THE build SHALL be reproducible: with `builds.mod_timestamp` and archive file `mtime` set to the commit timestamp, a second job builds the same tag and compares the checksums of binaries and archives (not SBOMs or signatures, which carry timestamps), failing on any difference.
- **AC-8 (scripted quickstart):** GoReleaser SHALL create a **draft** release. A job SHALL download the demo archive for linux/amd64, verify the checksum, the cosign bundle (`--certificate-identity-regexp` anchored to this repository's `release.yml@refs/tags/v`, issuer `https://token.actions.githubusercontent.com`), and the attestation (`gh attestation verify`), then run `demo.sh` and apply AC-3. Only if all of that passes is the release published. Only the release job gets `contents: write`, `id-token: write`, and `attestations: write`. The README's install commands SHALL be the same commands, which are extracted and run by this job.
- **AC-9:** ON every PR, `ci.yml` SHALL build snapshot archives (`goreleaser --snapshot`, no signing) and run the AC-1–AC-4 checks against them, so the release path can't rot between tags.

**Dependency hygiene (NFR-015)**
- **AC-10:** EVERY PR SHALL run `govulncheck ./...` (failing on a reachable known vulnerability), `actions/dependency-review-action`, and a gitleaks scan of the diff using the repository's `.gitleaks.toml` (spec 004 AC-16b). All actions are pinned to full commit SHAs (spec 001 AC-25).
- **AC-11:** THE release job SHALL also run `govulncheck` and fail the release on any reachable known vulnerability.

**Close-out**
- **AC-12:** THE README SHALL have a "Try it in 10 minutes" section (download, verify, run `demo.sh`), the results table, and the limitations (DESIGN.md §7.6).

## Out of scope
- A demo container image (cut-line item 2, §12.1).
- Homebrew and other package managers.
- A terminal recording or GIF (made later from `demo.sh`).
- Pushing the first tag: that is a publishing decision for the maintainer.

## Open questions
None.
