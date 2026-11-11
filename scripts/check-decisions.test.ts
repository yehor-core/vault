// check:decisions on fixtures: a past decision may only gain a note naming a decision added in the same change.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const SCRIPT = join(import.meta.dirname, 'check-decisions.ts');

const BASE = `# Decisions

D-01: Keys are sealed. Alternatives: none. Why: safety.
D-02: Scopes. Why: grouping. [Updated by D-03: names are strings.]
D-03: Scope names are strings. Why: origins.
`;

/** Runs check:decisions in a fixture repo whose decision log changed from BASE to `current`. */
function checkDecisions(current: string): { ok: boolean; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'check-decisions-'));
  try {
    mkdirSync(join(dir, 'docs'));
    writeFileSync(join(dir, 'base.md'), BASE);
    writeFileSync(join(dir, 'docs/DECISIONS.md'), current);
    const run = spawnSync(process.execPath, [SCRIPT, '--base-file', 'base.md'], { cwd: dir, encoding: 'utf8' });
    return { ok: run.status === 0, output: `${run.stdout}${run.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const NEW = 'D-04: Labels. Why: the task asks for them.\n';

const accepted: [label: string, current: string][] = [
  ['unchanged', BASE],
  ['a new decision appended', BASE + NEW],
  [
    'a past decision marked superseded by a new one',
    BASE.replace('Why: safety.', 'Why: safety. [Superseded by D-04.]') + NEW,
  ],
  [
    'a second note after an existing one',
    BASE.replace('names are strings.]', 'names are strings.] [Updated by D-04: labels too.]') + NEW,
  ],
  ['text outside decisions edited', BASE.replace('# Decisions', '# Decisions we make') + NEW],
];

const rejected: [label: string, current: string][] = [
  ['a past decision reworded', BASE.replace('Why: safety.', 'Why: integrity.')],
  ['a note naming no new decision', BASE.replace('Why: safety.', 'Why: safety. [Detail from S2-02: more.]')],
  ['a note naming an old decision', BASE.replace('Why: safety.', 'Why: safety. [Updated by D-03: x.]')],
  ['a past decision deleted', BASE.replace('D-03: Scope names are strings. Why: origins.\n', '')],
  ['an existing note edited', BASE.replace('names are strings.]', 'names are any strings.]')],
];

for (const [label, current] of accepted) {
  test(`accepts: ${label}`, () => {
    const { ok, output } = checkDecisions(current);
    assert.ok(ok, output);
  });
}

for (const [label, current] of rejected) {
  test(`rejects: ${label}`, () => {
    const { ok, output } = checkDecisions(current);
    assert.ok(!ok, output);
  });
}
