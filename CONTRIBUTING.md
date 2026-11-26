# Contributing to MCP Bulwark

Thanks for your interest. This project is **design-first and spec-driven**. Code is written only against approved specs. See [docs/WORKFLOW.md](docs/WORKFLOW.md).

## Ways to contribute right now (design phase)
- **Design feedback:** open a *Design feedback* issue that references a section of [DESIGN.md](DESIGN.md) (for example "§7.4 T-03").
- **Attack scenarios:** propose a new lab scenario with the *Lab scenario proposal* issue template. Only publicly known techniques, please.
- **Prior art:** point out tools or research the [IDEA.md](IDEA.md) prior-art table is missing.

## Pull requests
- Every code PR must trace to a spec in `specs/` and to requirement IDs (`FR-…`, `NFR-…`).
- Design changes go through a PR to `DESIGN.md`. Significant decisions need an ADR in `docs/adr/`.
- Write the tests first. A PR that changes behavior updates the docs in the same PR.
- Keep PRs small and focused, one spec task or a few related ones.

## Ground rules
- **No real secrets, personal data, or real customer data** in code, tests, fixtures, or issues. Use `example.com`, RFC 5737 IPs, and canary values.
- **Lab content must be harmless:** `LAB ONLY` banner, canary secrets, local sink only, no external network calls.
- **Security issues** go through [SECURITY.md](SECURITY.md), never public issues.
- Signed commits are encouraged.

## License
By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
