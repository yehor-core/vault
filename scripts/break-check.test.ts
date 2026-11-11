// break-check on a fixture repo whose `npm run typecheck` is a stand-in: it fails, naming test/types.test.ts, when
// src/code.ts holds BROKEN, and naming test/other.test.ts on OTHER. `npx` is a stand-in too: its vitest or Playwright
// run fails in the engines listed in FAKE_RED and passes in the others, so the engine handling runs without browsers.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
// The engine is the last argument break-check passes: `vitest run <test> -t <pattern> --project <engine>`, or
// `playwright test <test> -g <pattern> --project <engine>`. Each tool prints its own summary.
const NPX = `#!/bin/sh
tool=$1
for arg in "$@"; do engine=$arg; done
case " $FAKE_RED " in
  *" $engine "*) red=1 ;;
esac
if [ "$tool" = playwright ]; then
  if [ -n "$red" ]; then echo '  1 failed'; echo "  ✘  1 [$engine] › the guarded test"; exit 1; fi
  echo '  1 passed (1.0s)'; exit 0
fi
if [ -n "$red" ]; then echo ' Tests  1 failed (1)'; echo ' × the guarded test'; exit 1; fi
echo ' Tests  1 passed (1)'
`;

/** Runs break-check with `args` in a fresh fixture; returns its exit status, output and src/code.ts afterwards. */
function breakCheck(
  args: string[],
  batch?: unknown,
  fakeRed = '',
): { status: number | null; output: string; code: string } {
  const dir = mkdtempSync(join(tmpdir(), 'break-check-'));
  try {
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src/code.ts'), CODE);
    writeFileSync(join(dir, 'typecheck.cjs'), TYPECHECK);
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ scripts: { typecheck: 'node typecheck.cjs' } }));
    mkdirSync(join(dir, 'bin'));
    writeFileSync(join(dir, 'bin/npx'), NPX);
    chmodSync(join(dir, 'bin/npx'), 0o755);
    if (batch !== undefined) writeFileSync(join(dir, 'breaks.json'), JSON.stringify(batch));
    const env = { ...process.env, PATH: `${join(dir, 'bin')}:${process.env.PATH}`, FAKE_RED: fakeRed };
    const run = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: dir, encoding: 'utf8', env });
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

const vitestBreak = ['src/code.ts', 'true', 'false', 'test/unit/code.test.ts', 'the guarded test'];

test('a vitest break runs in Chromium, Firefox and WebKit by default, and is red only if red in each', () => {
  const all = breakCheck(vitestBreak, undefined, 'chromium firefox webkit');
  assert.equal(all.status, 0, all.output);
  assert.deepEqual(all.output.match(/^red in \w+/gm), ['red in chromium', 'red in firefox', 'red in webkit']);
  assert.equal(all.code, CODE);

  const two = breakCheck(vitestBreak, undefined, 'chromium firefox');
  assert.equal(two.status, 1, two.output);
  assert.match(two.output, /^NOT red in webkit/m);
});

test('a named engine runs the vitest break in that engine alone', () => {
  const webkit = breakCheck([...vitestBreak, 'webkit'], undefined, 'webkit');
  assert.equal(webkit.status, 0, webkit.output);
  assert.deepEqual(webkit.output.match(/red in \w+/g), ['red in webkit']);

  const batch = breakCheck(
    ['--batch', 'breaks.json'],
    [
      {
        file: 'src/code.ts',
        text: 'true',
        replacement: 'false',
        test: 'test/unit/code.test.ts',
        pattern: 'the guarded test',
        engine: 'firefox',
      },
    ],
    'chromium',
  );
  assert.equal(batch.status, 1, batch.output);
  assert.deepEqual(batch.output.match(/red in \w+/g), ['red in firefox']);
});

const e2eBreak = ['src/code.ts', 'true', 'false', 'test/e2e/demo.spec.ts', 'the guarded test'];

test('a break of an e2e test runs Playwright in Chromium, Firefox and WebKit, and is red only if red in each', () => {
  const all = breakCheck(e2eBreak, undefined, 'chromium firefox webkit');
  assert.equal(all.status, 0, all.output);
  assert.deepEqual(all.output.match(/^red in \w+/gm), ['red in chromium', 'red in firefox', 'red in webkit']);
  assert.equal(all.code, CODE);

  const two = breakCheck(e2eBreak, undefined, 'chromium firefox');
  assert.equal(two.status, 1, two.output);
  assert.match(two.output, /^NOT red in webkit: 1 passed/m);
});
