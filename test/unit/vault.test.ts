import { afterEach, describe, expect, test, vi } from 'vitest';
import { Vault } from '../../src/index.ts';
import {
  cleanup,
  deleteHeader,
  done,
  expectVaultError,
  openVault,
  readAll,
  readHeader,
  tickingClock,
  writeHeader,
} from './helpers.ts';

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const message = new TextEncoder().encode('message to sign');

async function verifyWithWebCrypto(publicKey: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>) {
  const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, signature, data);
}

describe('keys', () => {
  test('a generated key is listed with its public information', async () => {
    const { vault } = await openVault();
    const before = Date.now();
    const key = await vault.generate('ed25519');

    expect(key.type).toBe('ed25519');
    expect(key.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.publicKey).toHaveLength(32);
    expect(key.createdAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(await vault.list()).toEqual([key]);
  });

  test('a signature verifies under the public key with WebCrypto alone, without Vault', async () => {
    const { vault } = await openVault();
    const key = await vault.generate('ed25519');
    const signature = await vault.sign(key.id, message);

    expect(signature.type).toBe('ed25519');
    expect(signature.bytes).toHaveLength(64);
    expect(await verifyWithWebCrypto(key.publicKey, signature.bytes, message)).toBe(true);
    expect(await verifyWithWebCrypto(key.publicKey, signature.bytes, new TextEncoder().encode('other'))).toBe(false);
  });

  test('keys survive closing and reopening the vault', async () => {
    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    vault.close();

    const reopened = await Vault.open({ name });
    try {
      expect(await reopened.list()).toEqual([key]);
      const signature = await reopened.sign(key.id, message);
      expect(await verifyWithWebCrypto(key.publicKey, signature.bytes, message)).toBe(true);
    } finally {
      reopened.close();
    }
  });

  test('keys are listed oldest first', async () => {
    tickingClock();
    const { vault } = await openVault();
    const keys = [];
    for (let i = 0; i < 4; i++) keys.push(await vault.generate('ed25519'));
    expect((await vault.list()).map((k) => k.id)).toEqual(keys.map((k) => k.id));
  });

  test('delete removes only that key, and deleting a missing key is a no-op', async () => {
    const { vault } = await openVault();
    const [a, b] = [await vault.generate('ed25519'), await vault.generate('ed25519')];

    await vault.delete(a.id);
    await vault.delete(a.id);

    expect(await vault.list()).toEqual([b]);
    await expectVaultError(vault.sign(a.id, message), 'not-found');
    await expect(vault.sign(b.id, message)).resolves.toMatchObject({ type: 'ed25519' });
  });

  test('signing with an unknown key id fails with not-found', async () => {
    const { vault } = await openVault();
    await vault.generate('ed25519');
    const error = await expectVaultError(vault.sign('no-such-key', message), 'not-found');
    expect(error.retryable).toBe(false);
  });

  test('wipe removes every key and the vault header; the next generate starts a new vault', async () => {
    const { vault, name } = await openVault();
    const old = await vault.generate('ed25519');
    const oldHeader = await readHeader(name);

    await vault.wipe();

    expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    expect(await vault.list()).toEqual([]);
    await expectVaultError(vault.sign(old.id, message), 'not-found');

    const fresh = await vault.generate('ed25519');
    expect(await vault.list()).toEqual([fresh]);
    expect((await readHeader(name)).wrappingPublicKey).not.toEqual(oldHeader.wrappingPublicKey);
  });
});

describe('lifecycle', () => {
  test('opening and listing write nothing; the first generate creates the vault', async () => {
    const { vault, name } = await openVault();
    expect(await vault.list()).toEqual([]);
    expect(await readAll(name)).toEqual({ meta: [], keys: [] });

    await vault.generate('ed25519');
    await vault.generate('ed25519');
    const { meta, keys } = await readAll(name);
    expect(meta).toHaveLength(1);
    expect(keys).toHaveLength(2);
  });

  test('a closed vault rejects every call', async () => {
    const { vault } = await openVault();
    vault.close();
    await expect(vault.list()).rejects.toMatchObject({ name: 'InvalidStateError' });
    await expect(vault.generate('ed25519')).rejects.toMatchObject({ name: 'InvalidStateError' });
  });

  test('a call in flight when the vault is closed fails with InvalidStateError, not a retryable error', async () => {
    const { vault } = await openVault();
    await vault.generate('ed25519');
    const pending = [vault.generate('ed25519'), vault.list(), vault.sign('any', message)];
    vault.close();
    for (const call of pending) await expect(call).rejects.toMatchObject({ name: 'InvalidStateError' });
  });

  test('an unknown key type is a programming error (TypeError), not a VaultError', async () => {
    const { vault } = await openVault();
    await expect(vault.generate('secp256k1' as never)).rejects.toThrow(new TypeError('Unknown key type: secp256k1'));
  });
});

describe('errors', () => {
  test('an IndexedDB failure is reported as retryable unavailable, and a retry succeeds', async () => {
    const { vault } = await openVault();
    vi.spyOn(IDBDatabase.prototype, 'transaction').mockImplementationOnce(() => {
      throw new DOMException('simulated I/O failure', 'UnknownError');
    });

    const error = await expectVaultError(vault.list(), 'unavailable');
    expect(error.retryable).toBe(true);
    expect(error.cause).toMatchObject({ name: 'UnknownError' });
    expect(await vault.list()).toEqual([]);
  });

  test('the first generate writes header and key atomically: if the key write fails, no header remains', async () => {
    const { vault, name } = await openVault();
    const add = IDBObjectStore.prototype.add;
    vi.spyOn(IDBObjectStore.prototype, 'add').mockImplementation(function (this: IDBObjectStore, ...args) {
      if (this.name === 'keys') throw new DOMException('simulated quota failure', 'QuotaExceededError');
      return add.apply(this, args);
    });

    await expectVaultError(vault.generate('ed25519'), 'unavailable');
    expect(await readAll(name)).toEqual({ meta: [], keys: [] });
  });

  test('key records without a vault header are corrupted everywhere, never a new vault; only wipe recovers', async () => {
    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    await deleteHeader(name);

    await expectVaultError(vault.list(), 'corrupted');
    await expectVaultError(vault.generate('ed25519'), 'corrupted');
    await expectVaultError(vault.sign(key.id, message), 'corrupted');
    expect((await readAll(name)).meta).toEqual([]);

    await vault.wipe();
    await expect(vault.generate('ed25519')).resolves.toMatchObject({ type: 'ed25519' });
  });

  test('a header stored as undefined is corrupted, not absent and not a retryable failure', async () => {
    const { vault, name } = await openVault();
    await writeHeader(name, undefined);

    await expectVaultError(vault.list(), 'corrupted');
    await expectVaultError(vault.generate('ed25519'), 'corrupted');
  });

  test('a database without Vault stores is corrupted, not a retryable failure', async () => {
    const name = `test-${crypto.randomUUID()}`;
    (await done(indexedDB.open(name))).close(); // version 1, no stores: what a bare open(name) leaves
    try {
      await expectVaultError(Vault.open({ name }), 'corrupted');
    } finally {
      await done(indexedDB.deleteDatabase(name));
    }
  });

  test('a transient key generation failure is retried; a persistent one is retryable unavailable', async () => {
    const { vault } = await openVault();
    const generateKey = crypto.subtle.generateKey.bind(crypto.subtle) as (...args: unknown[]) => Promise<unknown>;
    let failures = 0;
    vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(((algorithm: unknown, ...rest: unknown[]) =>
      algorithm === 'Ed25519' && failures-- > 0
        ? Promise.reject(new DOMException('simulated engine failure', 'OperationError'))
        : generateKey(algorithm, ...rest)) as never);

    failures = 4;
    await expect(vault.generate('ed25519')).resolves.toMatchObject({ type: 'ed25519' });
    failures = 5;
    const error = await expectVaultError(vault.generate('ed25519'), 'unavailable');
    expect(error.retryable).toBe(true);
    expect(error.cause).toMatchObject({ name: 'OperationError' });
  });
});
