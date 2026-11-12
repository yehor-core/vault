import { afterEach, describe, expect, test, vi } from 'vitest';
import type { KeyInfo, Vault } from '../../src/index.ts';
import {
  cleanup,
  expectVaultError,
  holdGenerate,
  keyTypeCases,
  openContexts,
  readAll,
  readHeader,
  TEST_SCOPE,
  type KeyTypeCase,
} from './helpers.ts';

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
      const [a, b] = await openContexts();
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
      const [a, b] = await openContexts();
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
      const contexts = await openContexts();
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

  describe('concurrent first-time setup', () => {
    test('a first generate held while another context runs its first generate: both resolve under the winner header, the only one stored, and list and sign in both contexts', async () => {
      const [a, b] = await openContexts();
      const held = holdGenerate(type); // a has found no header and made its own, not stored yet

      const pending = a.scope.generate(type);
      await held.reached;
      const other = await b.scope.generate(type); // b's header is stored first: b wins
      const winnerHeader = await readHeader(a.name);
      held.release();
      const key = await pending; // a's header loses: a redoes against b's, without an error

      const { meta } = await readAll(a.name); // the header is the only record meta holds
      expect(meta).toEqual([expect.objectContaining({ wrappingPublicKey: winnerHeader.wrappingPublicKey })]);
      await expectKeysInEvery([a.vault, b.vault], [key, other], verify);
    });
  });

  describe('a stale context against a wipe', () => {
    test('a generate held while another context wipes: it resolves, and the vault holds only its new key, under a new header, which lists and signs in both contexts', async () => {
      const contexts = await openContexts();
      const [a, b] = contexts;
      const wiped = [await a.scope.generate(type), await a.vault.scope(OTHER_SCOPE).generate(type)];
      const wipedHeader = await readHeader(a.name);
      const held = holdGenerate(type); // a has read the header it will seal to

      const pending = a.scope.generate(type);
      await held.reached;
      await b.vault.wipe();
      held.release();
      const key = await pending; // a's header check fails: a redoes against the empty vault, without an error

      const { meta, keys } = await readAll(a.name);
      expect(meta).toHaveLength(1); // the header is the only record meta holds
      expect(meta[0]).not.toMatchObject({ wrappingPublicKey: wipedHeader.wrappingPublicKey });
      expect(keys).toEqual([expect.objectContaining({ scope: key.scope, id: key.id })]);
      await expectKeysInEvery([a.vault, b.vault], [key], verify);
      for (const { vault } of contexts) {
        expect(await vault.scope(OTHER_SCOPE).list()).toEqual([]);
        for (const old of wiped) await expectVaultError(vault.scope(old.scope).sign(old, message), 'not-found');
      }
    });

    test('after a wipe in one context, the other lists none of the old keys, and sign with a KeyInfo from before the wipe fails with not-found', async () => {
      const [a, b] = await openContexts();
      const wiped = [
        await a.scope.generate(type),
        await b.scope.generate(type),
        await b.vault.scope(OTHER_SCOPE).generate(type),
      ];
      await expectKeysInEvery([a.vault], wiped, verify); // a has read every key before the wipe

      await b.vault.wipe();

      for (const scope of [TEST_SCOPE, OTHER_SCOPE]) expect(await a.vault.scope(scope).list()).toEqual([]);
      for (const old of wiped) await expectVaultError(a.vault.scope(old.scope).sign(old, message), 'not-found');
    });
  });
});
