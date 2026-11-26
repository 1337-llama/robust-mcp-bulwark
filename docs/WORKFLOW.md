# Workflow: From Idea to Spec-Driven Build

MCP Bulwark moves through five stages. Each stage produces a specific artifact and has an exit gate. Gates keep the work disciplined, and the trail of documents they leave shows how the project was run.

| Stage | Artifact | Owner | Exit gate |
|---|---|---|---|
| 0. Idea | `IDEA.md` | Maintainer | Problem, goals, non-goals, MVP scope, and success metrics are agreed. Status → `Ready for design` |
| 1. Design | `DESIGN.md` + `docs/adr/*` | Maintainer + Claude | Every section filled, no `VERIFY:` items left, design review checklist passed. Status → `Approved` |
| 2. Specs | `specs/NNN-feature/{spec,plan,tasks}.md` | Maintainer + Claude | Spec traces to design requirements and has testable acceptance criteria. Status → `Ready` |
| 3. Build | Code, tests, docs | Claude + Maintainer review | All tasks done, CI green, acceptance criteria demonstrated |
| 4. Release | Public repo + tagged release | Maintainer | Repo made public with README demo, signed release, published threat model, and launch write-up |


## Working agreement

The maintainer has 1–2 hours per week, so the prompts below are adapted rather than followed literally. **Claude drafts with its recommendations applied and opens a pull request. The maintainer reviews it.** Each PR starts with a plain-language summary, a "Decisions for you" list (each decision stands unless changed), and a "Needs your input" list for things only the maintainer can decide. The full agreement is in [CLAUDE.md](../CLAUDE.md#working-agreement-the-maintainer-has-12-hours-per-week).

---

## Stage 0: Idea

**You edit `IDEA.md` directly.** Make the idea your own. Cut what you don't believe in, sharpen the scope, add your own field experience, and fill in "Maintainer notes". When you're done, have Claude stress-test it:

> Read `IDEA.md` and act as a skeptical principal engineer and a hiring manager for a senior security engineering role. Find (1) the weakest assumptions, (2) scope that is too large for one person over about 3 months for the MVP, (3) anything that already exists that I haven't accounted for, and (4) what would make it stand out more to an expert reviewer. Ask me questions. Don't edit the file yet.

Then:

> Update `IDEA.md` based on my answers. Set status to `Ready for design`.

## Stage 1: Design

The design document is written **one section at a time**, in the order below. Each step is a short conversation. Claude asks questions, you answer, and Claude drafts the section.

1. §1 Context, §2 Requirements (FR/NFR). Everything else traces back to these.
2. §3 Use cases
3. §4 Architecture (system context and components)
4. §7 Threat model. It is done this early on purpose, so security shapes the detailed design.
5. §5 Detailed component design, §6 Interfaces and data model
6. §8 AI/ML design
7. §9 Observability, §10 Test and evaluation strategy, §11 Deployment
8. §12 Milestones, §13 Alternatives, §15 Spec backlog

**Prompt to start a section:**

> We're working on `DESIGN.md`, section §N "<title>". Read `CLAUDE.md`, `IDEA.md`, the current `DESIGN.md`, and the ADRs in `docs/adr/`. Ask me the questions you need answered for this section, up to about 5, with your recommended answer for each. After I reply, draft the section, log any decisions, and update the document control table.

**Prompt for a significant decision:**

> Write an ADR for "<decision>" in `docs/adr/` using `templates/ADR_TEMPLATE.md`. Compare at least 3 options against our NFRs, recommend one, and link it from the DESIGN.md Decision Log.

**Prompt for design review (the exit gate):**

> Run a design review of `DESIGN.md` with the checklist below. For each item, report pass or fail with evidence, and list every remaining `VERIFY:` item. Then play three reviewers (a staff security engineer, an SRE, and an ML engineer) and give each one's top three concerns.

### Design review checklist

- [ ] Every FR/NFR is testable and numbered
- [ ] Every component in §4 has a detailed design in §5
- [ ] The threat model covers every trust boundary in the architecture diagram
- [ ] Every AI component has: an evaluation method, a failure mode analysis, and a non-AI fallback
- [ ] Every NFR has a way to measure it in §10
- [ ] Non-goals are explicit, and the MVP fits the milestone plan
- [ ] Alternatives are documented for each major decision
- [ ] No `VERIFY:` items remain, and all standards cited include version and ID
- [ ] The spec backlog covers the MVP completely

## Stage 2: Specs

Each spec is one vertical slice of functionality, small enough to build in a few focused sessions. Create it from `templates/spec/`:

```
specs/001-attack-suite/
├── spec.md    ← WHAT and WHY: user stories, acceptance criteria (EARS format), traced FR/NFR IDs
├── plan.md    ← HOW: modules, interfaces, data structures, test approach
└── tasks.md   ← ordered checklist of small, independently verifiable tasks
```

### Automated review loop (in use since 2026-11-26)
The maintainer has delegated the design and spec stages to an automated loop:

1. Claude writes a spec's `spec.md`, `plan.md`, and `tasks.md` **together in one PR**. Acceptance criteria use EARS syntax and trace to FR/NFR IDs. Tasks take under about an hour each, with the test first.
2. A separate, **independent reviewer session** reviews the PR and posts one comment ending in `Verdict: APPROVE` or `Verdict: CHANGES REQUESTED`.
3. Claude fixes the findings and replies on the PR. If there were blockers, the reviewer re-checks them.
4. **Who merges:** under the maintainer's standing instruction, Claude merges the PR once the reviewer reports no open blockers. The maintainer can stop the loop at any time, or review and merge a PR themselves. Merging sets the spec to `Ready`.
5. **The loop stops before Stage 3:** Claude checks in with the maintainer before writing any implementation code.

Without the loop, the original sequence applies: `spec.md` first and stop for review, then `plan.md`, then `tasks.md`.

## Stage 3: Build

> Implement `specs/NNN-<slug>/tasks.md`, task by task. For each task, write the test first, then the implementation, run the tests, and check the box. Stop and ask if the spec is ambiguous or wrong. Don't silently deviate; propose a spec change instead.

**Keep the docs in sync with the code.** If implementation shows the design was wrong, update the design and spec first, or write an ADR that supersedes the old decision. The docs should always describe the system as it actually is.

## Stage 4: Release

This project already has its own repository, so "graduating" means making it **public** and cutting the first release. Plan to go public at the **M1 write-up** (attack lab + baseline results), then tag `v0.1` at M4.

Release checklist: README with a demo GIF/asciinema, CODE_OF_CONDUCT.md, private vulnerability reporting enabled, CI badges, signed releases with SBOM and provenance, a published threat model, and a launch write-up explaining the design decisions.

---

## Signals of engineering leadership

The way this project is run is part of the portfolio. Keep the following visible:

- **Decision records (ADRs).** They show trade-off thinking.
- **Milestones and a public roadmap** (GitHub Projects/Milestones). They show scoping and planning.
- **Issue hygiene:** labels, `good first issue`, templates. These show that a project is set up to bring in contributors.
- **Quality gates:** CI, coverage, linting, dependency scanning, signed commits/releases.
- **Retrospectives:** a short `docs/retro/` note at each milestone. What worked, what didn't, and what changes.
