## What we do
We are building "Vault", a browserke key vault, as a take-home task.

## Context
- @docs/TASK.md - full task
- @docs/DECISIONS.md - decisions we make
- @docs/ROADMAP.md - defined slices. Build only the slice named under "## Task"; anything listed there as "Not included" belongs to a later slice.
- @DESIGN.md - design doc. Follow the filling rules in its header comment.

## How we work

### Decisions
- I own every decision. Before writing code for a slice, list the design decisions it requires and WAIT for my choice. Do not write code until I choose.
- Ask only about decisions that affect the public API, the storage format, a security guarantee, or are hard to reverse. Make smaller choices yourself (naming, file layout, helpers) and list them at the end of the slice. For each decision give 2–3 realistic options; drop options that clearly fail a TASK.md requirement.
- For each option state what it gives, what it costs, and which TASK.md requirement or threat-model case it touches. Recommend one and say what would make you pick another. Number decisions and letter options (1A, 2B) so I can answer in one line.
- Check every option against all of TASK.md and the later slices in ROADMAP.md, not just this slice. Migration code is not planned, so the storage format chosen now must serve later slices without a migration. Mark decisions that constrain later slices with "[constrains S<N>]" and say how.
- If my choice breaks a requirement in TASK.md or a decision already in DECISIONS.md, say so and quote it before writing code. If I keep it, record it in DECISIONS.md and in DESIGN.md §11 Known limitations.
- If a new design decision comes up while implementing (e.g. an IndexedDB transaction auto-commits across `await crypto.subtle…`, which changes how atomicity works), stop and ask in the same format. Don't decide it silently or work around it. 
- Record each decision I make in DECISIONS.md under "## Decisions we make while building" with the next ID (D-01, D-02…): decision, alternatives, why, what we give up. If it answers an item under "Decisions required by the task", put the ID next to that item. Never rewrite a past decision: add a new entry and mark the old one "superseded by D-NN". Decisions already in DECISIONS.md are binding; reopen one only if you find a conflict, and flag it. 

### Code
- Work in vertical slices. Keep code minimal — the task rewards simplicity.
- Code comments explain only the non-obvious *why*, in one or two lines (e.g. "no await between these requests: the transaction would auto-commit"). No tutorials in code.
- When you introduce a crypto or IndexedDB concept, explain it to me in chat in 2–3 plain sentences.

### Tests
- Each slice ends with tests that prove the hard properties it touches. Name each test after the property it proves.
- Tests must be able to fail: for each hard-property test, break the code it guards once (remove the check), show that the test goes red, then restore.

### Git
- One slice = one branch = one pull request. Before the first change, create `slice/S<N>-<short-name>` from an up-to-date `main`.
- Commit in small logical steps. Never commit the temporary breakage from the "tests must be able to fail" check.
- When the slice is done, push the branch and open a PR to `main` with `gh pr create`. Title: `S<N>: <slice name>`. Body: the end-of-slice report, the decision IDs made in this slice, and the test summary output.
- Never push to `main`, never merge, never force-push. I review and merge the PR myself.

## Done means
A slice is done only when all of these hold. Then stop and wait; don't start the next slice.
1. Tests pass in Chromium, Firefox and WebKit. Show the command and the summary output. If a test can't run in an engine, say which and why. 
2. Type checking passes with no errors.
3. DECISIONS.md is updated.
4. The DESIGN.md sections this slice touches are filled; every guarantee names its test or code.
5. The README property → test table has a row for each hard property this slice touches, with the engines it runs in.
6. The PR for this slice is open and its description contains the end-of-slice report below. Post the PR link in chat.

## End-of-slice report
- Guarantees: what this slice guarantees → the test or code that enforces it. Not guaranteed: what it doesn't protect, said plainly. No claim without a test or code reference. 
- Small choices you made yourself, in one line.
- 2–3 "break it" experiments to run by hand (tamper a record, cancel a prompt, open a second tab). For each: exact steps with a copy-paste console snippet (DevTools can't edit IndexedDB values), the expected result including the error class, and whether an automated test already covers it. If none does, say why it can't be automated (e.g. real biometrics, passkeys in Firefox/WebKit).

## Task
Implement slice S<N> from @docs/ROADMAP.md.