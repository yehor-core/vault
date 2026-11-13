/// <reference types="vite/client" />
import { expect, test } from 'vitest';
import { server } from 'vitest/browser';

const library = import.meta.glob<string>('../../src/**/*.ts', { query: '?raw', import: 'default', eager: true });
const packageJson = import.meta.glob<string>('../../package.json', { query: '?raw', import: 'default', eager: true });

// The third-party code DESIGN.md §3.3 justifies, at the exact version it names.
const JUSTIFIED_DEPENDENCIES = { '@noble/curves': '2.3.0', '@noble/hashes': '2.3.0' };

function bareImports(source: string): string[] {
  const specifiers = [...source.matchAll(/\b(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((match) => match[1] ?? '');
  return specifiers.filter((specifier) => !specifier.startsWith('.'));
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

// Reads code, not behaviour: it keeps the library free of UI frameworks and of third-party code DESIGN.md §3.3
// doesn't justify. A new package needs this list, package.json and §3.3 changed together.
test('the library imports only its own modules and the pinned @noble packages: no UI framework, no other third-party code', () => {
  expect(Object.keys(library)).toEqual(expect.arrayContaining(['../../src/index.ts', '../../src/seal.ts']));
  const packages = new Set(
    Object.values(library)
      .flatMap(bareImports)
      .map((specifier) => specifier.split('/').slice(0, 2).join('/')),
  );
  expect([...packages].sort()).toEqual(Object.keys(JUSTIFIED_DEPENDENCIES));
  const manifest: unknown = JSON.parse(Object.values(packageJson)[0] ?? '{}');
  expect(manifest).toHaveProperty('dependencies', JUSTIFIED_DEPENDENCIES);
});

// DESIGN.md §4.4: the application, not Vault, decides when to ask for persistent storage.
test('the library never requests persistent storage', () => {
  const callers = Object.entries(library)
    .filter(([, source]) => /\bnavigator\.storage\b|\.persist\s*\(/.test(source))
    .map(([file]) => file);
  expect(callers).toEqual([]);
});
