/// <reference types="vite/client" />
import { expect, test } from 'vitest';
import { keyTypes } from '../../src/key-types.ts';

// The core is every source file except the registry and the key-type modules, which alone may name a type.
const core = import.meta.glob<string>(['../../src/**/*.ts', '!../../src/key-types.ts', '!../../src/key-types/**'], {
  query: '?raw',
  import: 'default',
  eager: true,
});

// The one test that reads code instead of behaviour: it keeps "a new key type is one module and one
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
