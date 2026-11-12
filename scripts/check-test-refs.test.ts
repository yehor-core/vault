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

interface Fixture {
  readonly readme?: string;
  /** docs/ROADMAP.md; absent by default, which skips the status check. */
  readonly roadmap?: string;
  /** Messages of commits made on a branch off `base`; with none, the fixture is no git repo. */
  readonly commits?: readonly string[];
  /** The message of the commit being made, passed as --message. */
  readonly message?: string;
}

/** Runs check:refs in a fixture repo whose DESIGN.md is `design`, with `extraUnit` appended to the unit tests. */
function checkDesign(design: string, extraUnit = '', fixture: Fixture = {}): { ok: boolean; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'check-refs-'));
  try {
    mkdirSync(join(dir, 'test/unit'), { recursive: true });
    mkdirSync(join(dir, 'test/e2e'), { recursive: true });
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'test/unit/vault.test.ts'), UNIT + extraUnit);
    writeFileSync(join(dir, 'test/e2e/demo.spec.ts'), E2E);
    writeFileSync(join(dir, 'src/scope.ts'), SCOPE);
    writeFileSync(join(dir, 'DESIGN.md'), design);
    writeFileSync(join(dir, 'README.md'), fixture.readme ?? '');
    if (fixture.roadmap !== undefined) {
      mkdirSync(join(dir, 'docs'));
      writeFileSync(join(dir, 'docs/ROADMAP.md'), fixture.roadmap);
    }
    const args = [SCRIPT];
    // Inside a hook, git sets GIT_DIR, GIT_INDEX_FILE and more to the outer repo: kept, the fixture would commit there.
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GIT_')));
    if (fixture.commits) {
      const git = (...gitArgs: string[]) => {
        const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...gitArgs], { cwd: dir, env });
        assert.equal(run.status, 0, `git ${gitArgs.join(' ')}: ${run.stderr}`);
      };
      git('init', '-q', '-b', 'base');
      git('commit', '-q', '--allow-empty', '-m', 'base');
      git('checkout', '-q', '-b', 'ticket');
      for (const message of fixture.commits) git('commit', '-q', '--allow-empty', '-m', message);
      args.push('base');
    }
    if (fixture.message !== undefined) {
      writeFileSync(join(dir, 'COMMIT_EDITMSG'), fixture.message);
      args.push('--message', 'COMMIT_EDITMSG');
    }
    const run = spawnSync(process.execPath, args, { cwd: dir, encoding: 'utf8', env });
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

// A ticket the branch closes (`Refs #NN` in its commits or in the commit being made) is named nowhere in the docs.
const STALE = '| Correct under concurrency | first-time setup tested, wipe races not yet (#54) |\n';

test('fails on a ticket that a branch commit closes, in any wording, naming the line', () => {
  const { ok, output } = checkDesign(STALE, '', { commits: ['S4-03: tests\n\nRefs #54'] });
  assert.ok(!ok, output);
  assert.match(output, /DESIGN\.md:1: names #54, which this branch closes/);
});

test('fails on a ticket that the commit being made closes', () => {
  const { ok, output } = checkDesign(STALE, '', { message: 'S4-03: tests\n\nRefs #54\n' });
  assert.ok(!ok, output);
  assert.match(output, /DESIGN\.md:1: names #54/);
});

test('fails on a closed ticket in README.md too', () => {
  const { ok, output } = checkDesign('', '', { readme: STALE, commits: ['S4-03: tests\n\nRefs #54'] });
  assert.ok(!ok, output);
  assert.match(output, /README\.md:1: names #54/);
});

for (const [label, commits] of [
  ['another ticket', ['S4-02: tests\n\nRefs #53']],
  ['no ticket: the number is only in a subject', ['S4 plan: tickets #53, #54, #55']],
  ['a ticket whose number is a prefix', ['S4-99: tests\n\nRefs #5']],
] as const) {
  test(`accepts an open ticket's mark when the branch closes ${label}`, () => {
    const { ok, output } = checkDesign(STALE, '', { commits });
    assert.ok(ok, output);
  });
}

// The README status names the slice ROADMAP.md marks in progress, or, with none, the last one done.
const roadmap = (s3: string, s4: string) =>
  `## S3: Storage\nStatus: ${s3} · Spec: #35\n\n## S4: Multi-tab\nStatus: ${s4} · Spec: #51\n`;

for (const [slices, readme] of [
  [roadmap('done', 'in progress'), '> Status: S4 in progress. Built: …'],
  [roadmap('done', 'planned'), '> Status: S3 done. Built: …'],
] as const) {
  test(`accepts README "${readme}" against its roadmap`, () => {
    const { ok, output } = checkDesign('', '', { roadmap: slices, readme });
    assert.ok(ok, output);
  });
}

for (const [slices, readme] of [
  [roadmap('done', 'in progress'), '> Status: S2 in progress. Built: …'],
  [roadmap('done', 'in progress'), '> Status: S3 done. Built: …'],
  [roadmap('done', 'planned'), '> Status: S3 in progress. Built: …'],
  [roadmap('done', 'in progress'), '> Built: …'],
] as const) {
  test(`fails README "${readme}" against its roadmap`, () => {
    const { ok, output } = checkDesign('', '', { roadmap: slices, readme });
    assert.ok(!ok, output);
    assert.match(output, /README\.md: says ".*", ROADMAP\.md says "Status: S\d (in progress|done)"/);
  });
}
