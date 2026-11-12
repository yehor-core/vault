// Every test that DESIGN.md and README.md cite as `<file> › <title>` must still exist, so a renamed or
// deleted test can't leave a guarantee pointing at nothing. Whether the test proves the claim stays a review call.
// Code is checked the same way: `src/<file>.ts` must exist, and the spans right after it, joined only by ",",
// "and", "then" or "or" (`src/scope.ts` `#commitKeyRecord`, `untilUnchanged`), must be names that file contains.
// A "not tested" mark names, in its own table cell or sentence, the ticket that will test it (#NN) or says
// "not protected", so a mark can't outlive the work it waits for unnoticed.
//
// Citation forms: `storage › full title`, `storage › describe group › title` (each segment must exist),
// a title cut short with "…", a parameter written as <field>, cases listed as "a / b / c…", and a bare
// `› title` that continues the file named earlier on the same line.

import { existsSync, readdirSync, readFileSync } from 'node:fs';

const DOCS = ['DESIGN.md', 'README.md'];

// test('t'), describe('t'), test.each(cases)('t %s'), test.each<T>(cases)('t'), test.skipIf(cond)(\n 't'): the title
// is the first string argument. Cases may nest calls two deep.
const TEST_TITLE =
  /\b(?:test|it|describe)(?:\.\w+)*(?:<[^()]*?>)?\s*(?:\([^()]*(?:\([^()]*\)[^()]*)*\)\s*)?\(\s*(['"`])((?:\\.|[^\\])*?)\1/y;
// Where a test call starts. Each one must yield a title, or its citations would read as missing tests.
const TEST_CALL = /(?<![.\w])(?:test|it|describe)(?:\.\w+)*[<(]/g;
const PLACEHOLDER = /%[sdifjo#]|\$\{|\$\w/;
const CITATION = /^(?:([a-z0-9-]+) )?›\s*(.*)$/;
const SOURCE_FILE = /^src\/[\w./-]+\.ts$/;
const IDENTIFIER = /^#?[A-Za-z_$][\w$]*$/;
const NAME_JOINER = /^\s*(?:,\s*)?(?:(?:and|then|or)\s+)?$/;
const UNTESTED_MARK = /\bnot (?:yet )?tested\b|\bnot written yet\b/i;
const MARK_NAMED = /#\d+\b|\bnot protected\b/;

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
  const titles: string[] = [];
  for (const call of source.matchAll(TEST_CALL)) {
    TEST_TITLE.lastIndex = call.index;
    const match = TEST_TITLE.exec(source);
    if (match) titles.push((match[2] ?? '').replace(/\\(.)/g, '$1'));
    else {
      const line = source.slice(0, call.index).split('\n').length;
      failures.push(`${file}:${line}: a ${call[0].slice(0, -1)} call whose title check:refs can't read`);
    }
  }
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
  // A title that is only a placeholder (describe.each(keyTypeCases)('$type')) would match any citation.
  if (head.trim() === '') return false;
  return cited.startsWith(head) || head.startsWith(cited);
}

const failures: string[] = [];
let checked = 0;
let checkedCode = 0;

/** Whether `source` holds `name` as a whole name: `commitKeyRecord` is not `#commitKeyRecord`. */
function containsName(source: string, name: string): boolean {
  const escaped = name.replace(/[$]/g, '\\$&');
  return new RegExp(`(?<![\\w$#])${escaped}(?![\\w$])`).test(source);
}

/** Checks the code citations of one line: `parts` is the line split on backticks, so odd parts are code spans. */
function checkCode(parts: string[], where: string): void {
  for (let part = 1; part < parts.length; part += 2) {
    const file = parts[part] ?? '';
    if (!SOURCE_FILE.test(file)) continue;
    checkedCode += 1;
    if (!existsSync(file)) {
      failures.push(`${where}: \`${file}\` does not exist`);
      continue;
    }
    const source = readFileSync(file, 'utf8');
    for (let next = part + 2; next < parts.length; next += 2) {
      const name = parts[next] ?? '';
      if (!NAME_JOINER.test(parts[next - 1] ?? '') || !IDENTIFIER.test(name)) break;
      checkedCode += 1;
      if (!containsName(source, name)) failures.push(`${where}: \`${file}\` has no \`${name}\``);
    }
  }
}

/** A "not tested" mark must name its ticket or say "not protected" in the same table cell or sentence. */
function checkMarks(line: string, where: string): void {
  for (const cell of line.split('|')) {
    for (const sentence of cell.split(/(?<=\.)\s+/)) {
      const mark = UNTESTED_MARK.exec(sentence);
      if (mark && !MARK_NAMED.test(sentence)) {
        failures.push(`${where}: "${mark[0]}" names no ticket (#NN) and does not say "not protected"`);
      }
    }
  }
}

for (const doc of DOCS) {
  const lines = readFileSync(doc, 'utf8').split('\n');
  lines.forEach((line, index) => {
    const where = `${doc}:${index + 1}`;
    let prefix: string | undefined;
    const parts = line.split('`');
    checkCode(parts, where);
    checkMarks(line, where);
    const codeSpans = parts.filter((_, part) => part % 2 === 1);
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
  console.error(
    `\n${failures.length} problems in ${checked} test citations, ${checkedCode} code citations and the "not tested" marks.`,
  );
  process.exitCode = 1;
} else {
  console.log(
    `${checked} test citations and ${checkedCode} code citations resolve; every "not tested" mark names its ticket.`,
  );
}
