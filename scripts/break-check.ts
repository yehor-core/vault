// Break-check (CLAUDE.md, Tests): break the code a test guards, show the test red, restore the code.
//
//   npm run break-check -- <source file> <text to replace> <replacement> <test file> <test name pattern> [engine]
//
// The text must occur exactly once. The file is restored on every exit path, Ctrl-C included. Exit 0 means
// the test went red; exit 1 means the break went unnoticed (or no test matched the pattern).

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const [file, text, replacement, testFile, pattern, engine = 'chromium'] = process.argv.slice(2);
if (
  file === undefined ||
  text === undefined ||
  replacement === undefined ||
  testFile === undefined ||
  pattern === undefined
) {
  console.error(
    'usage: npm run break-check -- <source file> <text> <replacement> <test file> <test name pattern> [engine]',
  );
  process.exit(2);
}

const original = readFileSync(file, 'utf8');
const occurrences = original.split(text).length - 1;
if (occurrences !== 1) {
  console.error(`${file}: the text to replace occurs ${occurrences} times, not once`);
  process.exit(2);
}

const restore = () => writeFileSync(file, original);
process.on('SIGINT', () => {
  restore();
  process.exit(130);
});

writeFileSync(
  file,
  original.replace(text, () => replacement),
);
let output: string;
try {
  const run = spawnSync('npx', ['vitest', 'run', testFile, '-t', pattern, '--project', engine], { encoding: 'utf8' });
  output = `${run.stdout}${run.stderr}`;
} finally {
  restore();
}

// Red means a matched test failed: a pattern that matches nothing also exits non-zero, and is not a red run.
const failed = output.split('\n').filter((line) => line.includes('×'));
const summary =
  output
    .split('\n')
    .find((line) => /^\s*Tests\s/.test(line))
    ?.trim() ?? 'no test summary';
if (/Tests\s+\d+ failed/.test(output)) {
  console.log(`red in ${engine}: ${summary}`);
  for (const line of failed) console.log(`  ${line.trim()}`);
} else {
  console.log(`NOT red in ${engine}: ${summary}`);
  process.exitCode = 1;
}
