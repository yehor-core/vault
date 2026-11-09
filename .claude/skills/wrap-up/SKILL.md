---
name: wrap-up
description: Close a finished slice: mark it done in docs/ROADMAP.md and open the wrap-up PR with the slice report.
disable-model-invocation: true
---

Close slice S<N> once its last ticket is merged. The user names the slice; otherwise take the slice marked `Status: in progress` in `docs/ROADMAP.md`.

1. Check every issue on the slice's `Tickets:` line with `gh issue view <n> --json state`. Done when each one is closed. If any is open, name it and stop.
2. Create `S<N>/wrap-up` from an up-to-date `main`, and set the slice's `Status: done` in `docs/ROADMAP.md`.
3. Write the slice report from the slice's merged PRs and the `DESIGN.md` and README "Property → test" rows they changed:
   - **Guarantees**: each thing the slice guarantees → the test or code that enforces it. **Not guaranteed**: said plainly. Done when every claim has a reference.
   - **Break it**: 2–3 experiments to run by hand. For each: exact steps with a copy-paste console snippet (DevTools can't edit IndexedDB values), the expected result including the error code, and whether an automated test covers it; if none does, why it can't be automated.
4. Commit, push the branch, and open the PR: title `S<N>: wrap-up`, body the report. Post the link in chat.
