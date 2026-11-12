import { expect, test, type Page } from '@playwright/test';
import { webcrypto } from 'node:crypto';
import {
  generate,
  holdKeyGeneration,
  listAndSign,
  metaRecords,
  openDemo,
  startGenerate,
  type PageKey,
} from './contexts.ts';

// Several tabs on one vault (D-43): two pages of one browser context share its IndexedDB, as two tabs do.
// One interleaving per property; the unit tests in concurrency.test.ts run the others. One key type: the write
// path never names a type, and the unit tests run every registered one.

const message = 'message to sign';

/** Ed25519 verification in Node, independent of Vault and of the page. */
async function verifies(publicKey: number[], signature: number[], message: string): Promise<boolean> {
  const key = await webcrypto.subtle.importKey('raw', Uint8Array.from(publicKey), 'Ed25519', false, ['verify']);
  return webcrypto.subtle.verify('Ed25519', key, Uint8Array.from(signature), new TextEncoder().encode(message));
}

/** Each page lists exactly `keys` in the demo scope, and every key signs there with a signature that verifies. */
async function expectKeysInEvery(pages: Page[], keys: PageKey[]): Promise<void> {
  const byId = (keys: PageKey[]) =>
    keys.map(({ id, publicKey }) => ({ id, publicKey })).toSorted((x, y) => (x.id < y.id ? -1 : 1));
  for (const page of pages) {
    const listed = await listAndSign(page, message);
    expect(byId(listed)).toEqual(byId(keys));
    for (const { publicKey, signature } of listed) expect(await verifies(publicKey, signature, message)).toBe(true);
  }
}

test('concurrent generates from two tabs each store their key, which lists and signs in both tabs', async ({
  context,
}) => {
  const a = await openDemo(context);
  const b = await openDemo(context);
  const existing = await generate(b); // the vault exists: a first-time race is its own property
  const held = await holdKeyGeneration(a);

  const pending = await startGenerate(a);
  await held.reached;
  const other = await generate(b);
  await held.release();
  const key = await pending.settled();

  await expectKeysInEvery([a, b], [existing, key, other]);
});

test('concurrent first generates from two tabs converge on one vault: both keys list and sign in both tabs under the one header', async ({
  context,
}) => {
  const a = await openDemo(context);
  const b = await openDemo(context);
  const held = await holdKeyGeneration(a); // a has found no header and made its own, not stored yet

  const pending = await startGenerate(a);
  await held.reached;
  const other = await generate(b); // b's header is stored first: b wins
  const winner = await metaRecords(b);
  await held.release();
  const key = await pending.settled(); // a's header loses: a redoes against b's, without an error

  expect(winner).toHaveLength(1);
  expect(await metaRecords(a)).toEqual(winner);
  await expectKeysInEvery([a, b], [key, other]);
});
