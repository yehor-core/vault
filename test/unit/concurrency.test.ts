import { afterEach, describe, expect, test, vi } from 'vitest';
import type { KeyInfo, Vault } from '../../src/index.ts';
import { cleanup, expectVaultError, holdGenerate, keyTypeCases, openContexts, type KeyTypeCase } from './helpers.ts';

// Two contexts are two Vault.open() of one database in one page: each has its own connection, as two tabs do.
// A race is forced by holding one context's generate after it read the header, while the other writes.

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const message = new TextEncoder().encode('message to sign');
const OTHER_SCOPE = 'other';

const byId = (keys: KeyInfo[]) => keys.toSorted((a, b) => (a.id < b.id ? -1 : 1));

/** In every vault, each scope of `keys` lists exactly its keys, and every key signs with a signature that verifies. */
async function expectKeysInEvery(vaults: Vault[], keys: KeyInfo[], verify: KeyTypeCase['verify']): Promise<void> {
  for (const vault of vaults) {
    for (const scope of new Set(keys.map((key) => key.scope))) {
      expect(byId(await vault.scope(scope).list())).toEqual(byId(keys.filter((key) => key.scope === scope)));
    }
    for (const key of keys) {
      const { bytes } = await vault.scope(key.scope).sign(key, message);
      expect(await verify(key.publicKey, bytes, message)).toBe(true);
    }
  }
}

describe.each(keyTypeCases)('$type', ({ type, verify }) => {
  describe('no lost updates', () => {
    test('a generate held while another context generates in the same scope: both keys are stored, and list and sign in both contexts', async () => {
      const { contexts } = await openContexts();
      const [a, b] = contexts;
      const existing = await a.scope.generate(type); // the vault exists: a first-time race is its own property
      const held = holdGenerate(type);

      const pending = a.scope.generate(type);
      await held.reached;
      const other = await b.scope.generate(type);
      held.release();
      const key = await pending;

      await expectKeysInEvery([a.vault, b.vault], [existing, key, other], verify);
    });

    test('a generate held while another context generates in another scope: both keys are stored, and list and sign in both contexts', async () => {
      const { contexts } = await openContexts();
      const [a, b] = contexts;
      const existing = await a.scope.generate(type);
      const held = holdGenerate(type);

      const pending = a.scope.generate(type);
      await held.reached;
      const other = await b.vault.scope(OTHER_SCOPE).generate(type);
      held.release();
      const key = await pending;

      await expectKeysInEvery([a.vault, b.vault], [existing, key, other], verify);
    });

    test('a generate held while another context deletes a key of its scope: the new key is stored and the deleted one is gone, in both contexts', async () => {
      const { contexts } = await openContexts();
      const [a, b] = contexts;
      const kept = await a.scope.generate(type);
      const deleted = await a.scope.generate(type);
      const held = holdGenerate(type);

      const pending = a.scope.generate(type);
      await held.reached;
      await b.scope.delete(deleted);
      held.release();
      const key = await pending;

      await expectKeysInEvery([a.vault, b.vault], [kept, key], verify);
      for (const { scope } of contexts) await expectVaultError(scope.sign(deleted, message), 'not-found');
    });
  });
});
