# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root.
- **`docs/DECISIONS.md`**: this repo's decision log, used instead of `docs/adr/`. Decisions are numbered `D-NN` and are binding. Each entry is one line, so read entries one at a time:
  - The entries your ticket or spec names: `grep '^D-16:' docs/DECISIONS.md`.
  - The list of all decisions, one sentence each: `grep -o '^D-[0-9]*: [^.]*\.' docs/DECISIONS.md`. Then read the entries that touch your area.

If either file doesn't exist, **proceed silently**. Don't flag its absence; don't suggest creating it upfront. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates `GLOSSARY.md` lazily when terms actually get resolved.

## File structure

Single-context repo:

```
/
├── GLOSSARY.md
├── DESIGN.md
├── docs/
│   └── DECISIONS.md      ← decision log (D-01, D-02, …)
└── src/
```

## Recording decisions

Where a skill would write an ADR to `docs/adr/`, append an entry to `docs/DECISIONS.md` under "## Decisions we make while building" instead. Don't create `docs/adr/`.

- Use the next free ID (`D-NN`) and the existing format: decision, alternatives, why, what we give up.
- Start the entry with one short sentence that names the outcome and has no full stop inside it (so no file names): the list command above prints exactly that sentence.
- When it rests on an external fact (an audit, a release, a browser behaviour), name where that fact is recorded, so a reader can check it.
- If it answers an item under "## Decisions required by the task", put the ID next to that item.
- If it constrains a later slice in `docs/ROADMAP.md`, end the entry with `[constrains S<N>]` and say how.
- Never rewrite a past decision. Add a new entry and mark the old one at its end: `[Superseded by D-NN.]` or `[Updated by D-NN: …]`. `npm run check:decisions` enforces it. A detail of how a ticket implements a decision belongs in `DESIGN.md`, not in the decision.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag decision conflicts

If your output contradicts an existing decision in `docs/DECISIONS.md`, surface it explicitly rather than silently overriding:

> _Contradicts D-07 (storage format migration), but worth reopening because…_
