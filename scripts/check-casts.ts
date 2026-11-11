// Every type assertion (`x as T`, not `as const`) in src/ and demo/ names the check that makes it safe, in a
// comment holding "`as`:" on its line or the line above (CODING_STANDARDS.md, General). Whether the reason
// is true stays a review call; tests may cast freely.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOTS = ['src', 'demo'];
const REASON = '`as`:';
const CAST = /\bas\s+(?!const\b)[\w{([<'"]/;
const RENAME = /^\s*(?:import|export)\b[^;]*\{[^}]*\bas\b/;

function sourceFiles(dir: string): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries.flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith('.ts') ? [path] : [];
  });
}

/** Each line's code, with comments and string contents removed; a block comment may span lines. */
function codeLines(source: string): string[] {
  let inBlock = false;
  return source.split('\n').map((line) => {
    let code = '';
    for (let i = 0; i < line.length; i++) {
      if (inBlock) {
        if (line.startsWith('*/', i)) [inBlock, i] = [false, i + 1];
        continue;
      }
      if (line.startsWith('/*', i)) [inBlock, i] = [true, i + 1];
      else if (line.startsWith('//', i)) break;
      else if (`'"\``.includes(line.charAt(i))) {
        const quote = line.charAt(i);
        for (i++; i < line.length && line.charAt(i) !== quote; i++) if (line.charAt(i) === '\\') i++;
        code += `${quote}${quote}`;
      } else code += line.charAt(i);
    }
    return code;
  });
}

const failures: string[] = [];
for (const file of ROOTS.flatMap(sourceFiles)) {
  const lines = readFileSync(file, 'utf8').split('\n');
  codeLines(lines.join('\n')).forEach((code, index) => {
    if (!CAST.test(code) || RENAME.test(code)) return;
    const reasoned = [lines[index], lines[index - 1]].some((line) => line?.includes(REASON));
    if (!reasoned)
      failures.push(`${file}:${index + 1}: \`as\` without a reason: add // ${REASON} <the check that makes it safe>`);
  });
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log('Every type assertion in src/ and demo/ names its reason.');
