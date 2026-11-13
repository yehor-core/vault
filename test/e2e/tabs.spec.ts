import { expect, test, type Page } from '@playwright/test';
import {
  deleteKey,
  expectKeysSigned,
  generate,
  holdKeyGeneration,
  keepVault,
  protect,
  listAndSign,
  metaRecords,
  openDemo,
  startGenerate,
  type PageKey,
  verifies,
  watchChanges,
  wipe,
} from './contexts.ts';
import { addVirtualAuthenticator, answerPromptsFrom } from './passkeys.ts';

// Several tabs on one vault (D-43): two pages of one browser context share its IndexedDB, as two tabs do.
// One interleaving per property; the unit tests in concurrency.test.ts run the others. One key type: the write
// path never names a type, and the unit tests run every registered one.

const message = 'message to sign';

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
  const winnerMeta = await metaRecords(b);
  await held.release();
  const key = await pending.settled(); // a's header loses: a redoes against b's, without an error

  expect(winnerMeta).toHaveLength(1);
  expect(await metaRecords(a)).toEqual(winnerMeta);
  await expectKeysInEvery([a, b], [key, other]);
});

test('a generate held in one tab while another tab wipes resolves in a new vault: only its new key lists and signs in both tabs, under a new header', async ({
  context,
}) => {
  const a = await openDemo(context);
  const b = await openDemo(context);
  await generate(a);
  await generate(b);
  const wipedMeta = await metaRecords(a);
  const held = await holdKeyGeneration(a); // a has read the header it will seal to

  const pending = await startGenerate(a);
  await held.reached;
  await wipe(b);
  await held.release();
  const key = await pending.settled(); // a's header check fails: a redoes against the empty vault, without an error

  const meta = await metaRecords(b);
  expect(meta).toHaveLength(1); // the header is the only record meta holds
  expect(meta).not.toEqual(wipedMeta);
  await expectKeysInEvery([a, b], [key]);
});

test('protect in one tab: the other tab is told, reports locked, unlocks with one prompt and signs', async ({
  context,
  browserName,
}, testInfo) => {
  testInfo.skip(browserName !== 'chromium', 'Only Chromium’s virtual authenticator returns PRF results (D-80)');
  const a = await openDemo(context);
  await addVirtualAuthenticator(a, [], { prf: true });
  const b = await openDemo(context);
  const relayed = await answerPromptsFrom(b, a); // one authenticator, as one user's in both tabs
  const keys = [await generate(a), await generate(b)];
  const other = await keepVault(b);
  expect(await other.state()).toBe('unprotected');

  await protect(a);

  await expect.poll(other.changes).toBe(1);
  expect(await other.state()).toBe('locked');
  expect(await other.sign(message)).toEqual({ error: 'locked' });
  expect(relayed.prompts()).toBe(0);
  expect(await other.unlock()).toBeUndefined();
  expect(relayed.prompts()).toBe(1);
  expect(await other.state()).toBe('unlocked');
  await expectKeysSigned(await other.sign(message), keys, message);
  expect(relayed.prompts()).toBe(1);
});

test('a listener in one tab is called after generate, delete and wipe in another tab', async ({ context }) => {
  const a = await openDemo(context);
  const b = await openDemo(context);
  const changes = await watchChanges(b);

  const key = await generate(a);
  await expect.poll(changes.calls).toBe(1);
  await deleteKey(a, key);
  await expect.poll(changes.calls).toBe(2);
  await wipe(a);
  await expect.poll(changes.calls).toBe(3);
});
