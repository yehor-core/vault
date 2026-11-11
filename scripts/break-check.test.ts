// break-check's --typecheck and --batch modes on a fixture repo whose `npm run typecheck` is a stand-in: it fails,
// naming test/types.test.ts, when src/code.ts holds BROKEN, and naming test/other.test.ts on OTHER. The vitest
// mode needs real browsers and is not covered here.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const SCRIPT = join(import.meta.dirname, 'break-check.ts');
const CODE = 'export const ok = true;\n';
const TYPECHECK = `
const source = require('node:fs').readFileSync('src/code.ts', 'utf8');
if (source.includes('BROKEN')) { console.log('test/types.test.ts(1,1): error TS2344'); process.exit(1); }
if (source.includes('OTHER')) { console.log('test/other.test.ts(1,1): error TS2344'); process.exit(1); }
`;

/** Runs break-check with `args` in a fresh fixture; returns its exit status, output and src/code.ts afterwards. */
function breakCheck(args: string[], batch?: unknown): { status: number | null; output: string; code: string } {
  const dir = mkdtempSync(join(tmpdir(), 'break-check-'));
  try {
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src/code.ts'), CODE);
    writeFileSync(join(dir, 'typecheck.cjs'), TYPECHECK);
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ scripts: { typecheck: 'node typecheck.cjs' } }));
    if (batch !== undefined) writeFileSync(join(dir, 'breaks.json'), JSON.stringify(batch));
    const run = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: dir, encoding: 'utf8' });
    return {
      status: run.status,
      output: `${run.stdout}${run.stderr}`,
      code: readFileSync(join(dir, 'src/code.ts'), 'utf8'),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const typecheckBreak = (replacement: string) => [
  '--typecheck',
  'src/code.ts',
  'true',
  replacement,
  'test/types.test.ts',
];

test('--typecheck: red when the typecheck fails in the named test file, and the code is restored', () => {
  const { status, output, code } = breakCheck(typecheckBreak('BROKEN'));
  assert.equal(status, 0, output);
  assert.match(output, /red in typecheck/);
  assert.equal(code, CODE);
});

test('--typecheck: not red when the typecheck passes', () => {
  const { status, output, code } = breakCheck(typecheckBreak('false'));
  assert.equal(status, 1, output);
  assert.match(output, /NOT red in typecheck/);
  assert.equal(code, CODE);
});

test('--typecheck: not red when the typecheck fails only in another file', () => {
  const { status, output } = breakCheck(typecheckBreak('OTHER'));
  assert.equal(status, 1, output);
});

test('a text that does not occur exactly once is a usage error, and nothing is changed', () => {
  const { status, code } = breakCheck(['--typecheck', 'src/code.ts', 'e', 'BROKEN', 'test/types.test.ts']);
  assert.equal(status, 2);
  assert.equal(code, CODE);
});

test('--batch: runs every break alone and exits 0 only if each went red', () => {
  const red = { file: 'src/code.ts', text: 'true', replacement: 'BROKEN', test: 'test/types.test.ts', typecheck: true };
  const notRed = { ...red, replacement: 'false' };

  const all = breakCheck(['--batch', 'breaks.json'], [red, red]);
  assert.equal(all.status, 0, all.output);
  assert.equal(all.output.match(/red in typecheck/g)?.length, 2);

  const one = breakCheck(['--batch', 'breaks.json'], [red, notRed]);
  assert.equal(one.status, 1, one.output);
  assert.match(one.output, /1 of 2 breaks not red/);
  assert.equal(one.code, CODE);
});
