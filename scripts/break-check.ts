// Break-check (CLAUDE.md, Tests): break the code a test guards, show the test red, restore the code.
//
//   npm run break-check -- <source file> <text to replace> <replacement> <test file> <test name pattern> [engine]
//   npm run break-check -- --typecheck <source file> <text> <replacement> <test file>
//   npm run break-check -- --batch <breaks.json>
//
// Without an engine, a test break runs in Chromium, Firefox and WebKit, and is red only if it went red in each:
// the README's Property → test rows claim every listed engine. Name one engine for a fast loop, or for a guard that
// only one engine needs. A test file under test/e2e/ runs in Playwright (its projects carry the engine names),
// any other in vitest.
// --typecheck is for type-level tests: red means `npm run typecheck` failed with an error in <test file>.
// --batch reads a JSON array of { file, text, replacement, test, pattern?, engine?, typecheck? } and runs each
// break alone. The text must occur exactly once. The file is restored after every break, Ctrl-C included.
// Exit 0 means every break went red; exit 1 means one went unnoticed (or no test matched); exit 2 is a usage error.

import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';

interface Break {
  readonly file: string;
  readonly text: string;
  readonly replacement: string;
  readonly test: string;
  readonly pattern?: string;
  readonly engine?: string | undefined;
  readonly typecheck?: boolean;
}

// The browser instances in vitest.config.ts, and the projects in playwright.config.ts.
const ENGINES = ['chromium', 'firefox', 'webkit'] as const;

const USAGE = `usage: npm run break-check -- <source file> <text> <replacement> <test file> <test name pattern> [engine]
       npm run break-check -- --typecheck <source file> <text> <replacement> <test file>
       npm run break-check -- --batch <breaks.json>`;

function usage(message = USAGE): never {
  console.error(message);
  process.exit(2);
}

function parseArgs(args: string[]): Break[] {
  const [first, ...rest] = args;
  if (first === '--batch') {
    if (rest[0] === undefined) usage();
    const breaks: unknown = JSON.parse(readFileSync(rest[0], 'utf8'));
    if (!Array.isArray(breaks)) usage(`${rest[0]}: expected a JSON array of breaks`);
    return breaks.map((entry) => {
      const { file, text, replacement, test } = (entry ?? {}) as Partial<Break>; // `as`: each field is checked just below
      if ([file, text, replacement, test].some((value) => typeof value !== 'string')) {
        usage(`${rest[0]}: every break needs string file, text, replacement and test`);
      }
      return entry as Break; // `as`: its four required fields were checked above
    });
  }
  if (first === '--typecheck') {
    const [file, text, replacement, test] = rest;
    if (file === undefined || text === undefined || replacement === undefined || test === undefined) usage();
    return [{ file, text, replacement, test, typecheck: true }];
  }
  const [file, text, replacement, test, pattern, engine] = args;
  if (file === undefined || text === undefined || replacement === undefined || test === undefined || !pattern) usage();
  return [{ file, text, replacement, test, pattern, engine }];
}

// Every result line also goes to break-check.log (git-ignored), appended per run: the evidence the PR and the reviewer read.
const LOG = 'break-check.log';

function report(line: string, print = true): void {
  if (print) console.log(line);
  appendFileSync(LOG, `${line}\n`);
}

let restore = () => {};
process.on('SIGINT', () => {
  restore();
  process.exit(130);
});

/** Applies one break, runs its test, restores the file; true if the test went red. */
function breakOnce(spec: Break): boolean {
  const original = readFileSync(spec.file, 'utf8');
  const occurrences = original.split(spec.text).length - 1;
  if (occurrences !== 1) usage(`${spec.file}: the text to replace occurs ${occurrences} times, not once`);

  restore = () => writeFileSync(spec.file, original);
  writeFileSync(
    spec.file,
    original.replace(spec.text, () => spec.replacement),
  );
  try {
    return spec.typecheck ? typecheckRed(spec) : testRed(spec);
  } finally {
    restore();
    restore = () => {};
  }
}

function typecheckRed(spec: Break): boolean {
  const run = spawnSync('npm', ['run', '--silent', 'typecheck'], { encoding: 'utf8' });
  const output = `${run.stdout}${run.stderr}`;
  const errors = output.split('\n').filter((line) => line.includes(spec.test) && /error/.test(line));
  if (run.status !== 0 && errors.length > 0) {
    report(`red in typecheck: ${spec.test}`);
    for (const line of errors) report(`  ${line.trim()}`);
    return true;
  }
  report(`NOT red in typecheck: ${run.status === 0 ? 'it passed' : `no error in ${spec.test}`}`);
  return false;
}

function testRed(spec: Break): boolean {
  const engines = spec.engine === undefined ? ENGINES : [spec.engine];
  const redIn = spec.test.startsWith('test/e2e/') ? playwrightRedIn : vitestRedIn;
  // Every engine runs, even after one stays green, so the output shows the whole picture.
  return engines.map((engine) => redIn(spec, engine)).every(Boolean);
}

function vitestRedIn(spec: Break, engine: string): boolean {
  const args = ['vitest', 'run', spec.test, '-t', spec.pattern ?? '', '--project', engine];
  const run = spawnSync('npx', args, { encoding: 'utf8' });
  const output = `${run.stdout}${run.stderr}`;
  // Red means a matched test failed: a pattern that matches nothing also exits non-zero, and is not a red run.
  const summary =
    output
      .split('\n')
      .find((line) => /^\s*Tests\s/.test(line))
      ?.trim() ?? 'no test summary';
  if (/Tests\s+\d+ failed/.test(output)) {
    report(`red in ${engine}: ${summary}`);
    for (const line of output.split('\n').filter((l) => l.includes('×'))) report(`  ${line.trim()}`);
    return true;
  }
  report(`NOT red in ${engine}: ${summary}`);
  return false;
}

function playwrightRedIn(spec: Break, engine: string): boolean {
  const args = ['playwright', 'test', spec.test, '-g', spec.pattern ?? '', '--project', engine];
  const run = spawnSync('npx', args, { encoding: 'utf8' });
  const lines = `${run.stdout}${run.stderr}`.split('\n');
  // As with vitest: "No tests found" also exits non-zero, so only a failed count is red.
  const failed = lines.find((line) => /^\s*\d+ failed/.test(line));
  if (failed) {
    report(`red in ${engine}: ${failed.trim()}`);
    for (const line of lines.filter((l) => /^\s*✘/.test(l))) report(`  ${line.trim()}`);
    return true;
  }
  const summary = lines.find((line) => /^\s*\d+ passed/.test(line))?.trim() ?? 'no test summary';
  report(`NOT red in ${engine}: ${summary}`);
  return false;
}

const breaks = parseArgs(process.argv.slice(2));
report(`# ${new Date().toISOString()}`, false);
let notRed = 0;
for (const spec of breaks) {
  // A single break prints no header: its command line says it. The log holds many runs, so it always gets one.
  report(`== ${spec.file}: ${JSON.stringify(spec.text)} → ${JSON.stringify(spec.replacement)}`, breaks.length > 1);
  if (!breakOnce(spec)) notRed++;
}
if (breaks.length > 1)
  report(notRed === 0 ? `all ${breaks.length} breaks red` : `${notRed} of ${breaks.length} breaks not red`);
process.exitCode = notRed === 0 ? 0 : 1;
