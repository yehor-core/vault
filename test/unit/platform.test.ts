/// <reference types="vite/client" />
import { expect, test } from 'vitest';
import { server } from 'vitest/browser';
import manifestSource from '../../package.json?raw';

// The tests below read code, not behaviour. Comments count too: a match in one is a false red, never a false green.
const librarySources = import.meta.glob<string>('../../src/**/*.ts', { query: '?raw', import: 'default', eager: true });

// The third-party code DESIGN.md §3.3 justifies, at the exact version it names.
const JUSTIFIED_DEPENDENCIES = { '@noble/curves': '2.3.0', '@noble/hashes': '2.3.0' };

function bareImports(source: string): string[] {
  const specifiers = [...source.matchAll(/\b(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((match) => match[1] ?? '');
  return specifiers.filter((specifier) => !specifier.startsWith('.'));
}

function libraryFilesMatching(pattern: RegExp): string[] {
  return Object.entries(librarySources)
    .filter(([, source]) => pattern.test(source))
    .map(([file]) => file);
}

const engineUserAgent: Record<string, RegExp> = {
  chromium: /Chrome\//,
  firefox: /Firefox\//,
  webkit: /AppleWebKit\/(?!.*Chrome)/,
};

test('runs in the real browser engine it is configured for', () => {
  const expected = engineUserAgent[server.browser];
  if (!expected) throw new Error(`No user agent pattern for ${server.browser}`);
  expect(navigator.userAgent).toMatch(expected);
  expect(indexedDB).toBeInstanceOf(IDBFactory);
  expect(isSecureContext).toBe(true);
});

// Keeps the library free of UI frameworks and of third-party code DESIGN.md §3.3 doesn't justify. A new package
// needs a decision, this list, package.json and §3.3 changed together.
test('the library imports only its own modules and the pinned @noble packages: no UI framework, no other third-party code', () => {
  expect(Object.keys(librarySources)).toEqual(expect.arrayContaining(['../../src/index.ts', '../../src/seal.ts']));
  const packages = new Set(
    Object.values(librarySources)
      .flatMap(bareImports)
      .map((specifier) => specifier.split('/').slice(0, 2).join('/')),
  );
  expect([...packages].sort()).toEqual(Object.keys(JUSTIFIED_DEPENDENCIES));
  expect(JSON.parse(manifestSource)).toHaveProperty('dependencies', JUSTIFIED_DEPENDENCIES);
});

// DESIGN.md §4.4: the application, not Vault, decides when to ask for persistent storage.
test('the library never requests persistent storage', () => {
  expect(libraryFilesMatching(/\bnavigator\.storage\b|\.persist\s*\(/)).toEqual([]);
});

// TASK: IndexedDB is the only persistent store.
test('the library stores nothing outside IndexedDB: no Web Storage, cookies, Cache Storage or origin private file system', () => {
  expect(
    libraryFilesMatching(/\b(?:localStorage|sessionStorage|cookieStore|caches|getDirectory)\b|document\.cookie/),
  ).toEqual([]);
});
