# Security Policy

## Status
MCP Bulwark is in the **design phase** and has no released code yet. This policy applies from the first commit of code.

## Reporting a vulnerability
Please **do not open a public issue.** Report vulnerabilities privately through GitHub: go to the **Security** tab of this repository and choose **Report a vulnerability**.

Please include the affected version or commit, reproduction steps, and the impact you expect. Reports will be acknowledged, and a fix and disclosure timeline agreed with you before anything is published.

## Scope
| In scope | Out of scope |
|---|---|
| The gateway: proxying, pinning, analyzers, policy engine, taint tracking, audit log, CLI | Vulnerabilities in third-party MCP clients, servers, or models (report those to their vendors) |
| A way to bypass a policy decision or tamper with the audit log without detection | The intentionally malicious servers in `lab/` behaving maliciously. That is their purpose. |
| Lab servers that break their safety constraints (real network calls, touching real files outside the lab) | Prompt injection succeeding against an agent. MCP Bulwark limits the damage from injection; it does not claim to prevent it. |

## Coordinated disclosure by this project
If this project's benchmarking finds a vulnerability in a specific third-party product, it is reported privately to that vendor before any public write-up mentions it.
