# ADR-0003: Implementation language: Go

| Field | Value |
|---|---|
| Status | Accepted (amended in design 03) |
| Date | 2026-11-26 |
| Design sections | DESIGN.md §4, §11 |
| Requirements affected | FR-008, FR-020…FR-036, NFR-004, NFR-010, NFR-011, NFR-012, NFR-015 |

## Context
Bulwark is a stdio proxy that must add little latency (NFR-004), be trivial for a reviewer to install and run (NFR-011, a 10-minute evaluation), run on Linux and macOS (NFR-010), and ship as signed releases with an SBOM (NFR-012). It embeds a policy engine (ADR-0004). The lab servers and replay client need an MCP SDK. Claude writes the code and the maintainer reviews it, so readability in review matters too.

## Options considered
| Option | MCP SDK | Distribution | Performance | Policy engine fit | Portfolio signal |
|---|---|---|---|---|---|
| **Go** | Official Go SDK, stable since v1.0.0 (no-breaking-change guarantee); v1.7.0 supports protocol revision 2026-07-28 | Single static binary per platform; trivial cross-compilation | Excellent for proxies | **OPA is a native Go library**; Cedar has an official Go implementation | Strong: the language of most cloud-native security tooling (OPA, Trivy, Falco, Vault) |
| Python | Official SDK, very mature | `pipx`/containers; dependency and venv friction for reviewers | Adequate | OPA via subprocess or WASM; Cedar via bindings | Good (ubiquitous in security and AI) but a weaker "systems" signal |
| TypeScript | Reference SDK, most mature | `npx`, which is common for MCP servers, but needs Node | Adequate | OPA via WASM | Medium |
| Rust | Official SDK (`rmcp`); maturity not assessed, since Rust lost on review effort and OPA fit | Single binary | Excellent | Cedar is native Rust; OPA via WASM | Strong but slower iteration; harder to review |

## Decision
We will use **Go** for the gateway, the lab servers, the replay client, and the suite: one toolchain and one CI setup.

- The gateway handles JSON-RPC at the **message level** with its own strict parser (FR-028), so it stays transparent to fields it doesn't know. It uses SDK types only where helpful.
- The lab servers and replay client use the **official Go SDK** for protocol correctness.
- **Protocol baseline:** MCP revision **2026-07-28** (primary) plus **2025-11-25** (compatibility). 2026-07-28 removed the `initialize` handshake (each request carries its version in `_meta`), added `server/discover`, and replaced server-initiated requests with Multi Round-Trip Requests. Because both revisions will be in use at launch, the gateway detects the revision of each message, applies the same controls to both, and does not translate between them. Unsupported revisions are rejected in `enforce` mode (DESIGN.md §1.3, FR-036).

## Amendment (2026-11-26, design 02 review)
The first draft of this ADR said the gateway "forwards other negotiated versions unchanged". That described the 2025-11-25 handshake model, which 2026-07-28 removed. The baseline above replaces it.

## Amendment (2026-11-26, design 03)
No per-connection version pin is needed for the compatibility tests. The replay client sends raw scripted JSON-RPC rather than using the SDK (DESIGN.md §5.9, decision 29). A Go SDK v1.7.0 server answers a legacy `initialize` at the client's version when that version is supported and older than 2026-07-28 (`negotiatedVersion` in `mcp/shared.go` at tag v1.7.0, read 2026-11-26).

## Consequences
- **Easier:** download-and-run releases; native embedding of OPA; fast tests; `go test` drives the attack suite directly; `govulncheck` for dependency scanning.
- **Harder:** the ML classifier (v0.3) will need ONNX runtime bindings or a sidecar; acceptable since it's optional and later.
- **SDK pin:** the SDK is used only inside the lab servers, not by the gateway or the replay client. Each lab server is a short-lived process started per test, so a session leak, such as the one reported as fixed only in v1.8.0 prereleases, cannot build up. Spec 001 pins the latest stable v1.x at that time, and Dependabot keeps it current.
- **Revisit if:** the Go SDK falls behind the spec for features we need. The message-level gateway design limits that exposure.
