import { expect, test } from '@playwright/test';
import { webcrypto } from 'node:crypto';
import { generate, holdKeyGeneration, listAndSign, openDemo, startGenerate, type PageKey } from './contexts.ts';

// Several tabs on one vault (D-43): two pages of one browser context share its IndexedDB, as two tabs do.
// One interleaving per property; the unit tests in concurrency.test.ts run the others.

const message = 'message to sign';

/** Ed25519 verification in Node, independent of Vault and of the page. */
async function verifies(publicKey: number[], signature: number[]): Promise<boolean> {
  const key = await webcrypto.subtle.importKey('raw', Uint8Array.from(publicKey), 'Ed25519', false, ['verify']);
  return webcrypto.subtle.verify('Ed25519', key, Uint8Array.from(signature), new TextEncoder().encode(message));
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

  const byId = (keys: PageKey[]) =>
    keys.map(({ id, publicKey }) => ({ id, publicKey })).toSorted((x, y) => (x.id < y.id ? -1 : 1));
  for (const page of [a, b]) {
    const listed = await listAndSign(page, message);
    expect(byId(listed)).toEqual(byId([existing, key, other]));
    for (const { publicKey, signature } of listed) expect(await verifies(publicKey, signature)).toBe(true);
  }
});
