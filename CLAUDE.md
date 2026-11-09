## What we do
We are building "Vault", a browser key vault, as a take-home task.

## Context
Read these when the step needs them:
- `docs/TASK.md`: the full task; the source of truth for every requirement.
- `docs/ROADMAP.md`: slices S0–S7, each with a `Status · Spec · Tickets` line. A slice becomes one spec issue and several ticket issues. Build only what the current ticket asks; anything a slice lists as "Not included" belongs to a later slice.
- `docs/DECISIONS.md`: every design decision, D-NN (our ADR log).
- `DESIGN.md`: the design doc. Follow the filling rules in its header comment.
- `docs/CODING_STANDARDS.md`: code rules; `/code-review` checks against them.
- `GLOSSARY.md`: domain terms, written by `/grill-with-docs`. Use them in code, tickets and chat.

## Workflow
Roadmap → slice → spec → tickets → one PR per ticket. I start each step.
1. `/grill-with-docs` on the next planned slice in ROADMAP.md.
2. `/to-spec` publishes the slice spec as an issue. In ROADMAP.md, set the slice's `Spec: #<n>` and `Status: in progress`.
3. `/to-tickets` drafts vertical tickets with "Blocked by" and waits for my approval before publishing. Put their numbers in the slice's `Tickets:`.
4. For each ticket on the frontier (open, no open blocker): create the branch (see Git), then `/implement #<issue>`. It runs TDD and `/code-review`, and commits. If a design decision comes up that the spec doesn't settle, stop and ask; don't decide it silently or work around it.
5. I review and merge each PR. After the last ticket of a slice: the slice wrap-up below.

## Tests
- TDD at the seams agreed in the spec: the failing run before the implementation is the proof that the test can fail. For a test added to existing code, break the code it guards once, show red, restore.
- Never commit the temporary breakage.

## Git
- One ticket = one branch = one PR. Before `/implement`, create `S<N>/<NN>-<short-name>` from an up-to-date `main`.
- Commit messages reference the ticket (`Refs #<issue>`), so `/code-review` finds the spec.
- When the ticket is done: push, then `gh pr create`. Title `S<N>-<NN>: <ticket title>`. Body: `Closes #<issue>`, the decision IDs made, small choices made, the `/code-review` summary, the test summary output.
- Never push to `main`, never merge, never force-push.

## Ticket done means
1. Every acceptance criterion in the ticket is met.
2. `npm test` passes (unit tests in Chromium, Firefox and WebKit, then e2e); show the summary. If a test can't run in an engine, say which and why.
3. `npm run typecheck` passes.
4. `/code-review` findings are fixed or listed in the PR with a reason.
5. DECISIONS.md, the DESIGN.md sections and the README "Property → test" rows this ticket touches are updated; every guarantee names its test or code.
6. The PR is open; post the link in chat. Then stop and wait.

## Slice wrap-up (after the last ticket of a slice is merged)
Open one small PR `S<N>: wrap-up` that sets `Status: done` for the slice in ROADMAP.md, with this report in its body:
- Guarantees: what the slice guarantees → the test or code that enforces it. Not guaranteed: said plainly. No claim without a reference.
- 2–3 "break it" experiments to run by hand: exact steps with a copy-paste console snippet (DevTools can't edit IndexedDB values), the expected result including the error code, and whether an automated test covers it; if not, why it can't be automated.

## Task
Continue with the ticket or step I name.

## Agent skills

### Issue tracker

Issues live in GitHub Issues on `yehor-core/vault`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` at the root; decisions in `docs/DECISIONS.md`. See `docs/agents/domain.md`.
