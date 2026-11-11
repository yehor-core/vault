// A past decision is never rewritten (docs/agents/domain.md): compared with the base, each existing `D-NN:` line
// is unchanged, or only gains notes at its end, each naming a decision added in the same change
// ("[Superseded by D-31.]", "[Updated by D-31: …]").
//
//   npm run check:decisions -- [base ref]      base: the merge-base of HEAD and the ref (default origin/main)
//   npm run check:decisions -- --base-file <path>

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const LOG = 'docs/DECISIONS.md';
const DECISION = /^(D-\d+): /;
const NOTES = /^(?: \[[^\]]*\])+$/;

function decisions(text: string): Map<string, string> {
  const entries = new Map<string, string>();
  for (const line of text.split('\n')) {
    const id = DECISION.exec(line)?.[1];
    if (id) entries.set(id, line);
  }
  return entries;
}

function baseText(args: string[]): string {
  if (args[0] === '--base-file') return readFileSync(args[1] ?? '', 'utf8');
  const ref = args[0] ?? 'origin/main';
  const base = execFileSync('git', ['merge-base', ref, 'HEAD'], { encoding: 'utf8' }).trim();
  try {
    return execFileSync('git', ['show', `${base}:${LOG}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return ''; // no decision log at the base: every entry is new
  }
}

const before = decisions(baseText(process.argv.slice(2)));
const after = decisions(readFileSync(LOG, 'utf8'));
const added = new Set([...after.keys()].filter((id) => !before.has(id)));
const failures: string[] = [];

for (const [id, old] of before) {
  const now = after.get(id);
  if (now === undefined) {
    failures.push(`${id} was deleted; mark it superseded by a new decision instead`);
    continue;
  }
  if (now === old) continue;
  const appended = now.startsWith(old) ? now.slice(old.length) : undefined;
  const notes = appended !== undefined && NOTES.test(appended) ? (appended.match(/\[[^\]]*\]/g) ?? []) : [];
  const valid = notes.length > 0 && notes.every((note) => (note.match(/D-\d+/g) ?? []).some((ref) => added.has(ref)));
  if (!valid) {
    failures.push(
      `${id} was rewritten; a past decision only gains a note at its end naming a decision added in this change`,
    );
  }
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exitCode = 1;
} else {
  console.log(`${before.size} past decisions unchanged or only annotated; ${added.size} added.`);
}
