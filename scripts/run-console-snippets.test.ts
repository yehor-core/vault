// run-console-snippets: which blocks of a report run, and that they run in the dev demo with its console global.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { consoleSnippets } from './run-console-snippets.ts';

const SCRIPT = join(import.meta.dirname, 'run-console-snippets.ts');

test('only js blocks are snippets, in document order', () => {
  const markdown = [
    '# Report',
    '```js',
    'const a = 1;',
    '```',
    '```ts',
    'const skipped: number = 2;',
    '```',
    '```text',
    'skipped too',
    '```',
    '```js',
    'console.log(a);',
    '```',
  ].join('\n');
  assert.deepEqual(consoleSnippets(markdown), ['const a = 1;\n', 'console.log(a);\n']);
});

test('a report without js blocks has no snippets', () => {
  assert.deepEqual(consoleSnippets('```ts\nconst x = 1;\n```\n'), []);
});

/** Runs the script in Chromium on a report holding `snippet`. */
function run(snippet: string): { ok: boolean; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'console-snippets-'));
  try {
    const report = join(dir, 'report.md');
    writeFileSync(report, `\`\`\`js\n${snippet}\n\`\`\`\n`);
    const result = spawnSync(process.execPath, [SCRIPT, report, 'chromium'], { encoding: 'utf8' });
    return { ok: result.status === 0, output: `${result.stdout}${result.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('snippets run in the dev demo, where Vault is a console global, and their console output is printed', () => {
  const { ok, output } = run('const vault = await Vault.open();\nconsole.log(typeof vault.scope);');
  assert.ok(ok, output);
  assert.match(output, /^\[chromium\] function$/m);
});

test('a snippet that throws fails the run', () => {
  const { ok, output } = run("throw new Error('broken snippet');");
  assert.equal(ok, false);
  assert.match(output, /broken snippet/);
});
