// check:refs on fixtures: a citation of a test or code that exists resolves, every other kind fails, and so does a
// "not tested" mark that names no ticket. A loosened match (once, a placeholder-only title matched every citation)
// shows up here as a bad citation that passes.

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
  /x/.test(source); // a method named test, not a test call
  test.each(cases)('editing $field fails closed', () => {});
  test.each<[key: string, named: string[]]>([['a', ['b']]])('typed cases are named: %s', () => {});
});
describe.each(cases)('$type', () => {
  test('a test in every case', () => {});
});
`;
const E2E = `test('the demo works', async () => {});`;
const SCOPE = `
export class Scope {
  async #commitKeyRecord() {}
}
export function untilUnchanged() {}
`;

/** Runs check:refs in a fixture repo whose DESIGN.md is `design`, with `extraUnit` appended to the unit tests. */
function checkDesign(design: string, extraUnit = ''): { ok: boolean; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'check-refs-'));
  try {
    mkdirSync(join(dir, 'test/unit'), { recursive: true });
    mkdirSync(join(dir, 'test/e2e'), { recursive: true });
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'test/unit/vault.test.ts'), UNIT + extraUnit);
    writeFileSync(join(dir, 'test/e2e/demo.spec.ts'), E2E);
    writeFileSync(join(dir, 'src/scope.ts'), SCOPE);
    writeFileSync(join(dir, 'DESIGN.md'), design);
    writeFileSync(join(dir, 'README.md'), '');
    const run = spawnSync(process.execPath, [SCRIPT], { cwd: dir, encoding: 'utf8' });
    return { ok: run.status === 0, output: `${run.stdout}${run.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Runs check:refs in a fixture repo whose DESIGN.md cites `citation` in a table row. */
function checkRefs(citation: string, extraUnit = ''): { ok: boolean; output: string } {
  return checkDesign(`| A claim | \`${citation}\` |\n`, extraUnit);
}

const resolving = [
  'vault › a real test',
  'vault › group › a real test',
  'vault › a real…',
  'vault › editing <field> fails closed',
  'vault › typed cases are named: <case>',
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

// A call whose title the pattern can't read would drop out of the index unseen, and its citations read as missing.
test('fails, naming file and line, on a test call whose title it cannot read', () => {
  const { ok, output } = checkRefs('vault › a real test', "\ntest.each(f(g(h())))('too deep', () => {});\n");
  assert.ok(!ok, output);
  assert.match(output, /test\/unit\/vault\.test\.ts:12: /);
});

// Code citations: a span naming a file under src/, then the spans that follow it joined only by ",", "and", "then"
// or "or", each an identifier that file must contain.
const resolvingCode = [
  '`src/scope.ts`',
  '`src/scope.ts` `#commitKeyRecord`',
  '`src/scope.ts` `#commitKeyRecord`, `untilUnchanged`',
  '`src/scope.ts` `#commitKeyRecord` then `untilUnchanged`',
  '`src/scope.ts` `#commitKeyRecord` in one transaction; `generate` adds one', // prose ends the list
];

const failingCode = [
  '`src/vault.ts` `#commitKeyRecord`', // the file is not there
  '`src/scope.ts` `#headerForWrite`', // the file has no such name
  '`src/scope.ts` `#commitKeyRecord`, `untilChanged`',
  '`src/scope.ts` `commitKeyRecord`', // a private name is cited with its #
];

for (const line of resolvingCode) {
  test(`resolves code: ${line}`, () => {
    const { ok, output } = checkDesign(`| A claim | ${line} |\n`);
    assert.ok(ok, output);
  });
}

for (const line of failingCode) {
  test(`fails code: ${line}`, () => {
    const { ok, output } = checkDesign(`| A claim | ${line} |\n`);
    assert.ok(!ok, output);
  });
}

// A "not tested" mark names the ticket that will test it, or says "not protected", in its own table cell or sentence.
const namedMarks = [
  '| A claim | not tested yet (#54) |',
  '| A claim | multi-tab tests not written yet (#54) |',
  'A whole-browser crash is not tested: not protected.',
  '- **A stale context is implemented but not yet tested across tabs (#54)**, and nothing else.',
];

const unnamedMarks = [
  '| A claim | One transaction (the re-check is not tested until the multi-tab slice) |',
  '| A claim | multi-tab tests not written yet |',
  '| A claim | #54 | not tested yet |', // the ticket sits in another cell
  'The re-check is not tested. Ticket #54 is about something else.', // and in another sentence
];

for (const line of namedMarks) {
  test(`accepts mark: ${line}`, () => {
    const { ok, output } = checkDesign(`${line}\n`);
    assert.ok(ok, output);
  });
}

for (const line of unnamedMarks) {
  test(`fails mark: ${line}`, () => {
    const { ok, output } = checkDesign(`${line}\n`);
    assert.ok(!ok, output);
    assert.match(output, /DESIGN\.md:1: /);
  });
}
