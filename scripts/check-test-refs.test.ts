// check:refs on fixtures: a citation of a test that exists resolves, every other kind fails. A loosened match
// (once, a placeholder-only title matched every citation) shows up here as a bad citation that passes.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const SCRIPT = join(import.meta.dirname, 'check-test-refs.ts');

const UNIT = `
describe('group', () => {
  test('a real test', () => {});
  test.each(cases)('editing $field fails closed', () => {});
});
describe.each(cases)('$type', () => {
  test('a test in every case', () => {});
});
`;
const E2E = `test('the demo works', async () => {});`;

/** Runs check:refs in a fixture repo whose DESIGN.md cites `citation`. */
function checkRefs(citation: string): { ok: boolean; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'check-refs-'));
  try {
    mkdirSync(join(dir, 'test/unit'), { recursive: true });
    mkdirSync(join(dir, 'test/e2e'), { recursive: true });
    writeFileSync(join(dir, 'test/unit/vault.test.ts'), UNIT);
    writeFileSync(join(dir, 'test/e2e/demo.spec.ts'), E2E);
    writeFileSync(join(dir, 'DESIGN.md'), `| A claim | \`${citation}\` |\n`);
    writeFileSync(join(dir, 'README.md'), '');
    const run = spawnSync(process.execPath, [SCRIPT], { cwd: dir, encoding: 'utf8' });
    return { ok: run.status === 0, output: `${run.stdout}${run.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const resolving = [
  'vault › a real test',
  'vault › group › a real test',
  'vault › a real…',
  'vault › editing <field> fails closed',
  'vault › a test in every case',
  'e2e › the demo works',
];

const failing = [
  'vault › no such test',
  'vault › no such group › a real test',
  'vault › a placeholder-only title matches nothing', // describe.each('$type') must not match it
  'nope › a real test',
  '› a real test',
];

for (const citation of resolving) {
  test(`resolves: ${citation}`, () => {
    const { ok, output } = checkRefs(citation);
    assert.ok(ok, output);
  });
}

for (const citation of failing) {
  test(`fails: ${citation}`, () => {
    const { ok, output } = checkRefs(citation);
    assert.ok(!ok, output);
  });
}
