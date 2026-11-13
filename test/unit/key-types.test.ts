/// <reference types="vite/client" />
import { expect, test } from 'vitest';
import { isWellFormedKeyTypeName, keyTypes } from '../../src/key-types.ts';

// The core is every source file except the registry and the key-type modules, which alone may name a type, and
// protection.ts, which names the unlock passkey (D-78): no key type, but the same word.
const core = import.meta.glob<string>(
  ['../../src/**/*.ts', '!../../src/key-types.ts', '!../../src/key-types/**', '!../../src/protection.ts'],
  { query: '?raw', import: 'default', eager: true },
);

// A test that reads code instead of behaviour (as do two in platform.test.ts): it keeps "a new key type is one module and one
// registry entry" true. Comments count too, and case is ignored, so 'Ed25519' as a WebCrypto name is caught.
test('no core file names a registered key type', () => {
  expect(Object.keys(core)).toEqual(expect.arrayContaining(['../../src/scope.ts', '../../src/records.ts']));
  const named = Object.entries(core).flatMap(([file, source]) =>
    Object.keys(keyTypes)
      .filter((type) => new RegExp(`\\b${type}\\b`, 'i').test(source))
      .map((type) => `${file} names ${type}`),
  );
  expect(named).toEqual([]);
});

// An older build reads a type it doesn't know as incompatible only if the name is well-formed (D-21).
test('every registered key type name is well-formed, so an older build reads it as incompatible', () => {
  expect(Object.keys(keyTypes).filter((type) => !isWellFormedKeyTypeName(type))).toEqual([]);
});
