# ADR-0004: Policy engine: OPA / Rego (embedded)

| Field | Value |
|---|---|
| Status | Accepted (amended in design 03) |
| Date | 2026-11-26 |
| Design sections | DESIGN.md §4.2, §5.3 |
| Requirements affected | FR-023, FR-024, NFR-004, NFR-005 |

## Context
Every `tools/call` must get an allow, deny, or ask decision based on the tool, its arguments (paths, URLs, patterns), analyzer findings, and later session taint. Decisions must take well under the 5 ms latency budget (NFR-004), fail closed (NFR-005), and be testable. Policies are written by users, so they must be readable and come with a way to test them.

## Options considered
| Option | Expressiveness | Testing | Embedding in Go | Safety properties | Recognition |
|---|---|---|---|---|---|
| **OPA / Rego** | High: regex, glob, sets, string functions | Built-in unit-test framework (`opa test`) | Native Go library; prepared queries | Side-effect-free policies; we enforce default-deny in the decision combiner | Very high: CNCF graduated, common in job postings |
| Cedar | Good for authorization; **no regex** (only wildcard `like`) | Validator and formal analysis tooling | Official Go implementation | Default-deny, forbid-overrides-permit, analyzable | Growing (AWS Verified Permissions) |
| Custom YAML rules | Only what we build | Must be built ourselves | Trivial | Only what we build | None |
| Go code plugins | Unlimited | Go tests | Native | Hard to audit; policy becomes code | Low |

## Decision
We will embed **OPA (Rego v1, the default syntax since OPA 1.0)**, with these conventions:

- Policies add entries to `deny`, `ask`, and `allow` sets, each entry being a policy ID. The **gateway combines them**: any `deny` → deny; else any `ask` → ask; else any `allow` → allow; **else deny (default-deny)**. No policy can "un-deny".
- The gateway computes **derived attributes** before evaluation (cleaned absolute path, URL scheme and host, argument sizes), so policies don't re-implement fragile parsing such as `..` path tricks or URL confusion. Derived attributes are computed only for arguments whose **role** is declared in configuration and pinned with the tool, because argument names and meanings are chosen by the untrusted server.
- The decision input carries the **server identity** (configured ID plus command digest) and the tool's **pin status**, both supplied by the gateway. Example policies always match on them, so a server cannot obtain another server's permissions by naming its tool `read_file`.
- In v0.1, `ask` is treated as deny with an `approval_required` audit record. There is no interactive prompt (see DESIGN.md T-12); per-call approval arrives with the v0.2 approval broker.
- Policies are compiled with an OPA **capabilities** set that removes network and runtime built-ins (for example `http.send`, `net.lookup_ip_addr`, `opa.runtime`). Policies cannot make network calls (NFR-014) or read the process environment. *Amended in design 03:* the removed set is **every built-in that OPA marks `nondeterministic`** in the pinned version's capabilities file, derived mechanically rather than listed by hand. At OPA `main` on 2026-11-26 that is 11 built-ins: `http.send`, `net.lookup_ip_addr`, `opa.runtime`, `io.jwt.decode_verify`, `io.jwt.encode_sign`, `io.jwt.encode_sign_raw`, `json.match_schema`, `json.verify_schema`, `rand.intn`, `time.now_ns`, `uuid.rfc4122`. This also makes decisions deterministic (NFR-008).
- Queries are prepared at startup. v0.1 has no hot reload; policies change when the client restarts the server process (DESIGN.md §9). An evaluation error or timeout means deny (NFR-005).
- `bulwark policy test` wraps OPA's test runner, and example policies ship with tests.
- A simple YAML front-end that compiles to Rego for common cases is a later option, not v0.1.

## Consequences
- **Easier:** expressive argument constraints (FR-024); policy unit tests; a widely recognized skill on display.
- **Harder:** Rego has a learning curve for users. Mitigated by example policies, a documented input schema, and the combining convention, which keeps policies small.
- **Not chosen, but noted:** Cedar's analyzability and built-in forbid-overrides semantics are attractive. Our combining convention reproduces the forbid-overrides behavior. Revisit if formal policy analysis becomes a goal.
