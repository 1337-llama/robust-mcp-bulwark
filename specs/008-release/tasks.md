# Tasks 008: One-command demo and release pipeline

Each task takes under about an hour and can be verified on its own.

- [ ] **T1:** `demo.sh` and `make demo` (table and L-02 diff); `ci-summary --compare`. (AC-1–AC-3)
- [ ] **T2:** `.goreleaser.yaml` with the two archives, reproducible flags, and SBOMs; the archive-listing check. (AC-4, AC-5, AC-6)
- [ ] **T3:** `ci.yml`: snapshot build plus the demo checks; `govulncheck`, dependency review, and gitleaks. (AC-9, AC-10)
- [ ] **T4:** `release.yml`: build, cosign keyless signing, attestations, `govulncheck`. (AC-5, AC-6, AC-11)
- [ ] **T5:** `release.yml` jobs `reproducible` and `quickstart` (verify, then run the README's commands). (AC-7, AC-8)
- [ ] **T6:** README "Try it in 10 minutes", results table, and limitations. (AC-12)
- [ ] **T7:** Demonstrate every acceptance criterion; set status to `Done`. The first real tag is pushed by the maintainer.
