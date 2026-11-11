// check:casts on fixtures: every `as` in src/ and demo/ carries its reason, and nothing else is mistaken for one.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const SCRIPT = join(import.meta.dirname, 'check-casts.ts');

/** Runs check:casts in a fixture repo whose src/nested/code.ts holds `source`. */
function checkCasts(source: string, dir = 'src/nested'): { ok: boolean; output: string } {
  const root = mkdtempSync(join(tmpdir(), 'check-casts-'));
  try {
    mkdirSync(join(root, dir), { recursive: true });
    mkdirSync(join(root, 'test'), { recursive: true });
    writeFileSync(join(root, dir, 'code.ts'), source);
    writeFileSync(join(root, 'test/any.test.ts'), 'const x = y as never;\n'); // tests may cast freely
    const run = spawnSync(process.execPath, [SCRIPT], { cwd: root, encoding: 'utf8' });
    return { ok: run.status === 0, output: `${run.stdout}${run.stderr}` };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const accepted: [label: string, source: string][] = [
  ['as const', 'const options = { lowS: true } as const;'],
  ['the word in a line comment', '// stored as JS bytes'],
  ['the word in a block comment', '/**\n * kept as a CryptoKey\n */'],
  ['the word in a string', "throw new Error('used as a key');"],
  ['the word in a template', 'const m = `seen as ${x}`;'],
  ['an import rename', "import { secp256k1 as curve } from 'x';"],
  ['an export rename', "export { a as b } from './a.ts';"],
  ['a reason on the same line', 'return type as KeyTypeName; // `as`: checked by includes above'],
  ['a reason on the line above', "// `as`: TypeScript can't follow the runtime check\nreturn x as Signature;"],
];

const rejected: [label: string, source: string][] = [
  ['a bare cast', 'const n = value as number;'],
  ['a cast with an ordinary comment', 'const n = value as number; // fine'],
  ['a cast inside an expression', 'const t = (value as Record<string, unknown>).type;'],
  ['a cast after a closed block comment', '/* note */ const n = value as number;'],
  ['a reason two lines above', '// `as`: far away\n\nconst n = value as number;'],
];

for (const [label, source] of accepted) {
  test(`accepts: ${label}`, () => {
    const { ok, output } = checkCasts(source);
    assert.ok(ok, output);
  });
}

for (const [label, source] of rejected) {
  test(`rejects: ${label}`, () => {
    const { ok, output } = checkCasts(source);
    assert.ok(!ok, output);
    assert.match(output, /src\/nested\/code\.ts:\d+/);
  });
}

test('rejects: a bare cast in demo/', () => {
  const { ok, output } = checkCasts('const el = found as HTMLInputElement;', 'demo');
  assert.ok(!ok, output);
});
