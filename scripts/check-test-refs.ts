// Every test that DESIGN.md and README.md cite as `<file> › <title>` must still exist, so a renamed or
// deleted test can't leave a guarantee pointing at nothing. Whether the test proves the claim stays a review call.
//
// Citation forms: `storage › full title`, `storage › describe group › title` (each segment must exist),
// a title cut short with "…", a parameter written as <field>, cases listed as "a / b / c…", and a bare
// `› title` that continues the file named earlier on the same line.

import { existsSync, readdirSync, readFileSync } from 'node:fs';

const DOCS = ['DESIGN.md', 'README.md'];

// test('t'), describe('t'), test.each(cases)('t %s'), test.skipIf(cond)(\n 't'): the title is the first string argument.
const TEST_TITLE =
  /\b(?:test|it|describe)(?:\.\w+)*\s*(?:\([^()]*(?:\([^()]*\)[^()]*)*\)\s*)?\(\s*(['"`])((?:\\.|[^\\])*?)\1/g;
const PLACEHOLDER = /%[sdifjo#]|\$\{|\$\w/;
const CITATION = /^(?:([a-z0-9-]+) )?›\s*(.*)$/;

function testFiles(prefix: string): string[] {
  if (prefix === 'e2e') {
    return readdirSync('test/e2e')
      .filter((file) => file.endsWith('.spec.ts'))
      .map((file) => `test/e2e/${file}`);
  }
  return [`test/unit/${prefix}.test.ts`, `test/e2e/${prefix}.spec.ts`].filter((file) => existsSync(file));
}

const titleCache = new Map<string, string[]>();

function titlesIn(file: string): string[] {
  const cached = titleCache.get(file);
  if (cached) return cached;
  const source = readFileSync(file, 'utf8');
  const titles = [...source.matchAll(TEST_TITLE)].map((match) => (match[2] ?? '').replace(/\\(.)/g, '$1'));
  titleCache.set(file, titles);
  return titles;
}

function before(text: string, marker: string): string {
  const index = text.indexOf(marker);
  return index === -1 ? text : text.slice(0, index);
}

// "2 / '1' / true" lists cases of one title; a part with several words is a title of its own.
function citedTitles(text: string): string[] {
  const parts = text.split(' / ');
  const titles = parts.filter((part, index) => index === 0 || part.trim().includes(' '));
  return titles.map((part) => before(before(part, '…'), '<').trim()).filter((title) => title !== '');
}

// A parameterised title ("editing $field of …") is compared up to its first placeholder.
function matches(cited: string, title: string): boolean {
  const placeholder = title.search(PLACEHOLDER);
  if (placeholder === -1) return title.startsWith(cited);
  const head = title.slice(0, placeholder);
  return cited.startsWith(head) || head.startsWith(cited);
}

const failures: string[] = [];
let checked = 0;

for (const doc of DOCS) {
  const lines = readFileSync(doc, 'utf8').split('\n');
  lines.forEach((line, index) => {
    const where = `${doc}:${index + 1}`;
    let prefix: string | undefined;
    const codeSpans = line.split('`').filter((_, part) => part % 2 === 1);
    for (const span of codeSpans) {
      const citation = CITATION.exec(span);
      if (!citation) continue;
      prefix = citation[1] ?? prefix;
      const text = citation[2] ?? '';
      if (text === '') continue;
      if (prefix === undefined) {
        failures.push(`${where}: \`${span}\` names no test file earlier on its line`);
        continue;
      }
      const files = testFiles(prefix);
      if (files.length === 0) {
        failures.push(`${where}: \`${span}\`: no test file for "${prefix} ›"`);
        continue;
      }
      for (const cited of text.split(' › ').flatMap(citedTitles)) {
        checked += 1;
        const found = files.some((file) => titlesIn(file).some((title) => matches(cited, title)));
        if (!found) failures.push(`${where}: "${prefix} › ${cited}" matches no test in ${files.join(', ')}`);
      }
    }
  });
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  console.error(`\n${failures.length} of ${checked} test citations don't resolve.`);
  process.exitCode = 1;
} else {
  console.log(`${checked} test citations resolve.`);
}
