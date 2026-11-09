# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root.
- **`docs/DECISIONS.md`**: this repo's decision log, used instead of `docs/adr/`. Read the entries that touch the area you're about to work in. Decisions are numbered `D-NN` and are binding.

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
- If it answers an item under "## Decisions required by the task", put the ID next to that item.
- If it constrains a later slice in `docs/ROADMAP.md`, end the entry with `[constrains S<N>]` and say how.
- Never rewrite a past decision. Add a new entry and mark the old one "superseded by D-NN".

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag decision conflicts

If your output contradicts an existing decision in `docs/DECISIONS.md`, surface it explicitly rather than silently overriding:

> _Contradicts D-07 (storage format migration), but worth reopening because…_
