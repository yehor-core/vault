import { afterEach, describe, expect, test, vi } from 'vitest';
import { ed25519 } from '../../src/ed25519.ts';
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

async function verifyWithWebCrypto(
  publicKey: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
) {
  const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, signature, data);
}

describe('keys', () => {
  test('a generated key is listed with its public information', async () => {
    const { scope } = await openVault();
    const before = Date.now();
    const key = await scope.generate('ed25519');

    expect(key.type).toBe('ed25519');
    expect(key.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.publicKey).toHaveLength(32);
    expect(key.createdAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(await scope.list()).toEqual([key]);
  });

  test('a signature verifies under the public key with WebCrypto alone, without Vault', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('ed25519');
    const signature = await scope.sign(key.id, message);

    expect(signature.type).toBe('ed25519');
    expect(signature.bytes).toHaveLength(64);
    expect(await verifyWithWebCrypto(key.publicKey, signature.bytes, message)).toBe(true);
    expect(await verifyWithWebCrypto(key.publicKey, signature.bytes, new TextEncoder().encode('other'))).toBe(false);
  });

  test('keys survive closing and reopening the vault', async () => {
    const { vault, scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    vault.close();

    const reopened = await Vault.open({ name });
    try {
      const again = reopened.scope(scope.name);
      expect(await again.list()).toEqual([key]);
      const signature = await again.sign(key.id, message);
      expect(await verifyWithWebCrypto(key.publicKey, signature.bytes, message)).toBe(true);
    } finally {
      reopened.close();
    }
  });

  test('keys are listed oldest first', async () => {
    tickingClock();
    const { scope } = await openVault();
    const keys = [];
    for (let i = 0; i < 4; i++) keys.push(await scope.generate('ed25519'));
    expect((await scope.list()).map((k) => k.id)).toEqual(keys.map((k) => k.id));
  });

  test('delete removes only that key, and deleting a missing key is a no-op', async () => {
    const { scope } = await openVault();
    const [a, b] = [await scope.generate('ed25519'), await scope.generate('ed25519')];

    await scope.delete(a.id);
    await scope.delete(a.id);

    expect(await scope.list()).toEqual([b]);
    await expectVaultError(scope.sign(a.id, message), 'not-found');
    await expect(scope.sign(b.id, message)).resolves.toMatchObject({ type: 'ed25519' });
  });

  test('signing with an unknown key id fails with not-found', async () => {
    const { scope } = await openVault();
    await scope.generate('ed25519');
    const error = await expectVaultError(scope.sign('no-such-key', message), 'not-found');
    expect(error.retryable).toBe(false);
  });

  test('wipe removes every key and the vault header; the next generate starts a new vault', async () => {
    const { vault, scope, name } = await openVault();
    const old = await scope.generate('ed25519');
    const oldHeader = await readHeader(name);

    await vault.wipe();

    expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    expect(await scope.list()).toEqual([]);
    await expectVaultError(scope.sign(old.id, message), 'not-found');

    const fresh = await scope.generate('ed25519');
    expect(await scope.list()).toEqual([fresh]);
    expect((await readHeader(name)).wrappingPublicKey).not.toEqual(oldHeader.wrappingPublicKey);
  });
});

describe('scopes', () => {
  test('keys generated in one scope are listed only there, and an unused scope lists nothing', async () => {
    const { vault } = await openVault();
    const [a, b] = [vault.scope('app-a'), vault.scope('app-b')];
    const keyA = await a.generate('ed25519');
    const keyB = await b.generate('ed25519');

    expect(await a.list()).toEqual([keyA]);
    expect(await b.list()).toEqual([keyB]);
    expect(await vault.scope('unused').list()).toEqual([]);
    expect(await vault.scope('app-a').list()).toEqual([keyA]); // a scope is its name: a second view sees the same keys
  });

  test('a malformed scope name is a TypeError; a name of 1 to 1024 code units is a scope of its own', async () => {
    const { vault } = await openVault();
    const malformed = ['', 'x'.repeat(1025), '\uD800', 'a\uDC00b', 1, null, undefined, {}, new String('app')];
    for (const name of malformed) expect(() => vault.scope(name as never)).toThrow(TypeError);

    // Compared exactly: 'é' precomposed and decomposed are two scopes, and so are names that differ in case.
    const names = ['x', 'x'.repeat(1024), 'https://app.example:8443', 'é', 'é', 'App', 'app', '😀'];
    for (const name of names) await vault.scope(name).generate('ed25519');
    for (const name of names) {
      const scope = vault.scope(name);
      expect(scope.name).toBe(name);
      expect(await scope.list()).toHaveLength(1);
    }
  });

  test('a key of another scope is not-found by sign and untouched by delete', async () => {
    const { vault } = await openVault();
    const [a, b] = [vault.scope('app-a'), vault.scope('app-b')];
    const key = await a.generate('ed25519');

    await expectVaultError(b.sign(key.id, message), 'not-found');
    await b.delete(key.id);
    expect(await a.list()).toEqual([key]);
  });

  test('a Scope has no path to its Vault: it can neither wipe nor be retargeted at another scope', async () => {
    const { vault } = await openVault();
    const scope = vault.scope('app-a');
    const key = await scope.generate('ed25519');

    // Everything reachable from the scope object, up to Object.prototype: no Vault, no vault-wide operation.
    const reachable: unknown[] = [];
    for (let o: object | null = scope; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
      for (const name of Reflect.ownKeys(o)) {
        const { value, get } = Object.getOwnPropertyDescriptor(o, name) ?? {};
        reachable.push(name, value, get?.call(scope));
      }
    }
    expect(reachable).not.toContain(vault);
    expect(reachable.some((value) => value instanceof Vault)).toBe(false);
    expect(reachable).not.toContain('wipe');
    expect(reachable).not.toContain('scope');

    expect(() => Object.assign(scope, { name: 'app-b' })).toThrow(TypeError);
    expect(scope.name).toBe('app-a');
    expect(await scope.list()).toEqual([key]);
  });

  test('wipe removes the keys of every scope and the header in one transaction', async () => {
    const { vault, name } = await openVault();
    const [a, b] = [vault.scope('app-a'), vault.scope('app-b')];
    await a.generate('ed25519');
    await b.generate('ed25519');
    const transaction = vi.spyOn(IDBDatabase.prototype, 'transaction');

    await vault.wipe();

    expect(transaction).toHaveBeenCalledTimes(1);
    expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    expect(await a.list()).toEqual([]);
    expect(await b.list()).toEqual([]);
  });

  test('scope() after close() throws InvalidStateError, and closing ends every scope, calls in flight included', async () => {
    const { vault } = await openVault();
    const [a, b] = [vault.scope('app-a'), vault.scope('app-b')];
    const key = await a.generate('ed25519');
    const pending = [a.list(), b.generate('ed25519'), a.sign(key.id, message)];
    vault.close();

    expect(() => vault.scope('app-c')).toThrow(expect.objectContaining({ name: 'InvalidStateError' }));
    for (const call of [...pending, a.list(), b.list(), b.delete(key.id)]) {
      await expect(call).rejects.toMatchObject({ name: 'InvalidStateError' });
    }
  });
});

describe('lifecycle', () => {
  test('opening and listing write nothing; the first generate creates the vault', async () => {
    const { scope, name } = await openVault();
    expect(await scope.list()).toEqual([]);
    expect(await readAll(name)).toEqual({ meta: [], keys: [] });

    await scope.generate('ed25519');
    await scope.generate('ed25519');
    const { meta, keys } = await readAll(name);
    expect(meta).toHaveLength(1);
    expect(keys).toHaveLength(2);
  });

  test('a closed vault rejects every call', async () => {
    const { vault, scope } = await openVault();
    const key = await scope.generate('ed25519');
    vault.close();
    const calls = [
      scope.generate('ed25519'),
      scope.list(),
      scope.sign(key.id, message),
      scope.delete(key.id),
      vault.wipe(),
    ];
    for (const call of calls) await expect(call).rejects.toMatchObject({ name: 'InvalidStateError' });
  });

  test('sign rejects data that is not a Uint8Array instead of signing something else', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('ed25519');
    // new Uint8Array('hello') is empty: coercing would sign the empty message and report success.
    for (const data of ['hello', [1, 2, 3], new ArrayBuffer(4), new DataView(new ArrayBuffer(4))]) {
      await expect(scope.sign(key.id, data as never)).rejects.toThrow(new TypeError('data must be a Uint8Array'));
    }
  });

  test('a call in flight when the vault is closed fails with InvalidStateError, not a retryable error', async () => {
    const { vault, scope } = await openVault();
    await scope.generate('ed25519');
    const pending = [scope.generate('ed25519'), scope.list(), scope.sign('any', message)];
    vault.close();
    for (const call of pending) await expect(call).rejects.toMatchObject({ name: 'InvalidStateError' });
  });

  test('an unknown key type is a programming error (TypeError), not a VaultError', async () => {
    const { scope } = await openVault();
    await expect(scope.generate('secp256k1' as never)).rejects.toThrow(new TypeError('Unknown key type: secp256k1'));
  });
});

describe('errors', () => {
  test('an IndexedDB failure is reported as retryable unavailable, and a retry succeeds', async () => {
    const { scope } = await openVault();
    vi.spyOn(IDBDatabase.prototype, 'transaction').mockImplementationOnce(() => {
      throw new DOMException('simulated I/O failure', 'UnknownError');
    });

    const error = await expectVaultError(scope.list(), 'unavailable');
    expect(error.retryable).toBe(true);
    expect(error.cause).toMatchObject({ name: 'UnknownError' });
    expect(await scope.list()).toEqual([]);
  });

  test('the first generate writes header and key atomically: if the key write fails, no header remains', async () => {
    const { scope, name } = await openVault();
    const add = IDBObjectStore.prototype.add;
    vi.spyOn(IDBObjectStore.prototype, 'add').mockImplementation(function (this: IDBObjectStore, ...args) {
      if (this.name === 'keys') throw new DOMException('simulated quota failure', 'QuotaExceededError');
      return add.apply(this, args);
    });

    await expectVaultError(scope.generate('ed25519'), 'unavailable');
    expect(await readAll(name)).toEqual({ meta: [], keys: [] });
  });

  test('a write that aborts at commit, after its body returned, fails as unavailable and stores nothing', async () => {
    const { scope } = await openVault();
    // The same key pair twice gives the same id, so the second add fails asynchronously with ConstraintError.
    const pair = await ed25519.generate();
    vi.spyOn(ed25519, 'generate').mockResolvedValue(pair);
    const first = await scope.generate('ed25519');

    const error = await expectVaultError(scope.generate('ed25519'), 'unavailable');
    expect(error.cause).toMatchObject({ name: 'ConstraintError' });
    expect(await scope.list()).toEqual([first]);
  });

  test('wipe is one transaction: aborted midway, it fails as unavailable and the header and keys remain', async () => {
    const { vault, scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    const before = await readAll(name);
    const clear = IDBObjectStore.prototype.clear;
    vi.spyOn(IDBObjectStore.prototype, 'clear').mockImplementation(function (this: IDBObjectStore) {
      const request = clear.call(this);
      if (this.name === 'keys') this.transaction.abort(); // the header is already cleared in this transaction
      return request;
    });

    await expectVaultError(vault.wipe(), 'unavailable');
    expect(await readAll(name)).toEqual(before);
    expect(await scope.list()).toEqual([key]);
  });

  test('key records without a vault header are corrupted everywhere, never a new vault; only wipe recovers', async () => {
    const { vault, scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    await deleteHeader(name);

    await expectVaultError(scope.list(), 'corrupted');
    await expectVaultError(scope.generate('ed25519'), 'corrupted');
    await expectVaultError(scope.sign(key.id, message), 'corrupted');
    expect((await readAll(name)).meta).toEqual([]);

    await vault.wipe();
    await expect(scope.generate('ed25519')).resolves.toMatchObject({ type: 'ed25519' });
  });

  test('a header stored as undefined is corrupted, not absent and not a retryable failure', async () => {
    const { scope, name } = await openVault();
    await writeHeader(name, undefined);

    await expectVaultError(scope.list(), 'corrupted');
    await expectVaultError(scope.generate('ed25519'), 'corrupted');
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
    const { scope } = await openVault();
    const generateKey = crypto.subtle.generateKey.bind(crypto.subtle) as (...args: unknown[]) => Promise<unknown>;
    let failures = 0;
    vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(((algorithm: unknown, ...rest: unknown[]) =>
      algorithm === 'Ed25519' && failures-- > 0
        ? Promise.reject(new DOMException('simulated engine failure', 'OperationError'))
        : generateKey(algorithm, ...rest)) as never);

    failures = 2; // not 4: the remaining real attempts must absorb WebKit's own ~0.7% failure rate
    await expect(scope.generate('ed25519')).resolves.toMatchObject({ type: 'ed25519' });
    failures = 5;
    const error = await expectVaultError(scope.generate('ed25519'), 'unavailable');
    expect(error.retryable).toBe(true);
    expect(error.cause).toMatchObject({ name: 'OperationError' });
  });
});
