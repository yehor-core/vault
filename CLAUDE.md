## What we do
We are building "Vault", a browser key vault, as a take-home task.

## Context
Read these when the step needs them:
- `docs/TASK.md`: the full task; the source of truth for every requirement.
- `docs/ROADMAP.md`: slices S0–S7, each with a `Status · Spec · Tickets` line. A slice becomes one spec issue and several ticket issues. Build only what the current ticket asks; anything a slice lists as "Not included" belongs to a later slice.
- `DESIGN.md`: the design doc. Follow the filling rules in its header comment.
- `docs/CODING_STANDARDS.md`: code rules; `/code-review` checks against them.

## Workflow
Roadmap → slice → spec → tickets → one PR per ticket. I start each step.
1. `/grill-with-docs` on the next planned slice in ROADMAP.md.
2. `/to-spec` publishes the slice spec as an issue. In ROADMAP.md, set the slice's `Spec: #<n>` and `Status: in progress`.
3. `/to-tickets` drafts vertical tickets with "Blocked by" and waits for my approval before publishing. Each ticket names the decisions that bind it (`Decision: D-NN`). Put their numbers in the slice's `Tickets:`.
4. For each ticket on the frontier (open, no open blocker): create the branch (see Git), then `/implement #<issue>`. It runs TDD and `/code-review`, and commits.
5. I review and merge each PR. After the last ticket of a slice is merged: `/wrap-up`.

## Tests
- A test written before its code proves it can fail by its red run. A test added to existing code is break-checked: break the code it guards once, show it red, restore, and commit only the restored code.

## Git
- One ticket = one branch = one PR. Before `/implement`, create `S<N>/<NN>-<short-name>` from an up-to-date `main`.
- Commit messages reference the ticket (`Refs #<issue>`), so `/code-review` finds the spec.
- In a new worktree, run `npx husky` once before the first commit: it creates the git-ignored `.husky/_` that runs the pre-commit hook (D-26).
- When the ticket is done: push, then `gh pr create`. Title `S<N>-<NN>: <ticket title>`. Body: `Closes #<issue>` first, then the `/pr` template, then a short `/code-review` summary.
- The planning records of a slice (what steps 1–3 change in GLOSSARY.md, DECISIONS.md and ROADMAP.md) share one branch, `S<N>/00-plan`, and one PR, opened after `/to-tickets`.

## Ticket done means
1. Every acceptance criterion in the ticket is met.
2. `npm test` passes (unit tests in Chromium, Firefox and WebKit, then e2e); show the summary. If a test can't run in an engine, say which and why.
3. `npm run typecheck` and `npm run check:refs` pass.
4. `/code-review` findings are fixed or listed in the PR with a reason.
5. DECISIONS.md, the DESIGN.md sections and the README "Property → test" rows this ticket touches are updated; every guarantee names its test or code.
6. The PR is open; post the link in chat. Then stop and wait.

## Agent skills

### Issue tracker

Issues live in GitHub Issues on `yehor-core/vault`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` at the root; decisions in `docs/DECISIONS.md`. See `docs/agents/domain.md`.
