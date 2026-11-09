import { afterEach, describe, expect, test, vi } from 'vitest';
import { ed25519 } from '../../src/ed25519.ts';
import { Vault, type KeyInfo } from '../../src/index.ts';
import {
  cleanup,
  deleteHeader,
  done,
  expectVaultError,
  openVault,
  readAll,
  readHeader,
  SCOPE,
  tickingClock,
  types,
  verifyOutsideVault,
  writeHeader,
} from './helpers.ts';

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const message = new TextEncoder().encode('message to sign');
const publicKeyLength = { ed25519: 32, secp256k1: 33 };

describe.each(types)('keys of type %s', (type) => {
  test('a generated key is listed with its public information, in its scope', async () => {
    const { scope } = await openVault();
    const before = Date.now();
    const key = await scope.generate(type);

    expect(key).toMatchObject({ type, scope: SCOPE });
    expect(key.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.publicKey).toHaveLength(publicKeyLength[type]);
    expect(key.createdAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(key).not.toHaveProperty('label');
    expect(await scope.list()).toEqual([key]);
  });

  test('a signature verifies under the public key without Vault, and only for the signed data', async () => {
    const { scope } = await openVault();
    const key = await scope.generate(type);
    const signature = await scope.sign(key, message);

    expect(signature.type).toBe(type);
    expect(signature.bytes).toHaveLength(64);
    expect(await verifyOutsideVault(key, signature, message)).toBe(true);
    expect(await verifyOutsideVault(key, signature, new TextEncoder().encode('other'))).toBe(false);
  });

  test('keys survive closing and reopening the vault', async () => {
    const { vault, scope, name } = await openVault();
    const key = await scope.generate(type, { label: 'kept' });
    vault.close();

    const reopened = await Vault.open({ name });
    try {
      const keys = reopened.scope(SCOPE);
      expect(await keys.list()).toEqual([key]);
      expect(await verifyOutsideVault(key, await keys.sign(key, message), message)).toBe(true);
    } finally {
      reopened.close();
    }
  });

  test('delete removes only that key, and deleting a missing key is a no-op', async () => {
    const { scope } = await openVault();
    const [a, b] = [await scope.generate(type), await scope.generate(type)];

    await scope.delete(a);
    await scope.delete(a);

    expect(await scope.list()).toEqual([b]);
    await expectVaultError(scope.sign(a, message), 'not-found');
    await expect(scope.sign(b, message)).resolves.toMatchObject({ type });
  });
});

describe('keys', () => {
  test('keys of every type are listed together, oldest first', async () => {
    tickingClock();
    const { scope } = await openVault();
    const keys = [];
    for (let i = 0; i < 4; i++) keys.push(await scope.generate(types[i % types.length]!));
    expect((await scope.list()).map((k) => k.id)).toEqual(keys.map((k) => k.id));
  });

  test('signing with an unknown key id fails with not-found', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('ed25519');
    const error = await expectVaultError(scope.sign({ ...key, id: 'no-such-key' }, message), 'not-found');
    expect(error.retryable).toBe(false);
  });

  test('wipe removes every key in every scope and the vault header; the next generate starts a new vault', async () => {
    const { vault, scope, name } = await openVault();
    const other = vault.scope('other');
    const [old, otherOld] = [await scope.generate('ed25519'), await other.generate('secp256k1')];
    const oldHeader = await readHeader(name);

    await vault.wipe();

    expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    expect(await scope.list()).toEqual([]);
    expect(await other.list()).toEqual([]);
    await expectVaultError(scope.sign(old, message), 'not-found');
    await expectVaultError(other.sign(otherOld, message), 'not-found');

    const fresh = await scope.generate('ed25519');
    expect(await scope.list()).toEqual([fresh]);
    expect((await readHeader(name)).wrappingPublicKey).not.toEqual(oldHeader.wrappingPublicKey);
  });
});

describe('scopes', () => {
  test('scopes keep keys apart: each lists only its own, and deleting in one leaves the other', async () => {
    const { vault } = await openVault();
    const [a, b] = [vault.scope('a'), vault.scope('b')];
    const keyA = await a.generate('ed25519');
    const keyB = await b.generate('ed25519');

    expect(await a.list()).toEqual([keyA]);
    expect(await b.list()).toEqual([keyB]);
    expect(keyB).toMatchObject({ scope: 'b' });

    await a.delete(keyA);
    expect(await a.list()).toEqual([]);
    expect(await b.list()).toEqual([keyB]);
    await expect(b.sign(keyB, message)).resolves.toMatchObject({ type: 'ed25519' });
  });

  test('the same name gives the same scope, from any Vault instance on the database', async () => {
    const { vault, name } = await openVault();
    const key = await vault.scope('shared').generate('secp256k1');
    expect(await vault.scope('shared').list()).toEqual([key]);

    const second = await Vault.open({ name });
    try {
      expect(await second.scope('shared').list()).toEqual([key]);
    } finally {
      second.close();
    }
  });

  test("a key of another scope is a TypeError in sign and delete, never that scope's key", async () => {
    const { vault } = await openVault();
    const [a, b] = [vault.scope('a'), vault.scope('b')];
    const keyA = await a.generate('ed25519');

    await expect(b.sign(keyA, message)).rejects.toThrow(new TypeError(`Key ${keyA.id} belongs to scope a, not b`));
    await expect(b.delete(keyA)).rejects.toThrow(TypeError);
    // Re-labelled as b's, it is still not in b: the stored key is [scope, id].
    await expectVaultError(b.sign({ ...keyA, scope: 'b' }, message), 'not-found');
    expect(await a.list()).toEqual([keyA]);
  });

  test('scope names are well-formed strings of 1 to 1024 characters; anything else is a TypeError', async () => {
    const { vault } = await openVault();
    for (const name of ['', 'x'.repeat(1025), 'x\uD800', '\uDC00', 1, null, undefined]) {
      expect(() => vault.scope(name as never)).toThrow(TypeError);
    }
    for (const name of ['x', 'x'.repeat(1024), 'https://app.example:8443', 'ключі 🔑']) {
      expect(vault.scope(name).name).toBe(name);
    }
  });

  test('a Scope exposes its name and key operations, and no way to reach its Vault', async () => {
    const { scope } = await openVault();
    expect(Object.keys(scope)).toEqual(['name']);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(scope)).sort()).toEqual(['constructor', 'delete', 'generate', 'list', 'sign']);
  });
});

describe('labels', () => {
  test('a label is stored with the key and listed without any secret', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('secp256k1', { label: 'Savings 💰' });
    expect(key.label).toBe('Savings 💰');
    expect(await scope.list()).toEqual([key]);
    await expect(scope.sign(key, message)).resolves.toMatchObject({ type: 'secp256k1' });
  });

  test('labels are well-formed strings of 1 to 256 characters; anything else is a TypeError and stores nothing', async () => {
    const { scope, name } = await openVault();
    for (const label of ['', 'x'.repeat(257), 'x\uD800', 1, null]) {
      await expect(scope.generate('ed25519', { label: label as never })).rejects.toThrow(TypeError);
    }
    expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    await expect(scope.generate('ed25519', { label: 'x'.repeat(256) })).resolves.toMatchObject({ label: 'x'.repeat(256) });
  });
});

describe('lifecycle', () => {
  test('opening and listing write nothing; the first generate creates the vault', async () => {
    const { scope, name } = await openVault();
    expect(await scope.list()).toEqual([]);
    expect(await readAll(name)).toEqual({ meta: [], keys: [] });

    await scope.generate('ed25519');
    await scope.generate('secp256k1');
    const { meta, keys } = await readAll(name);
    expect(meta).toHaveLength(1);
    expect(keys).toHaveLength(2);
  });

  test('a closed vault rejects every call, on the vault and on its scopes', async () => {
    const { vault, scope } = await openVault();
    const key = await scope.generate('ed25519');
    vault.close();
    const calls = [scope.generate('ed25519'), scope.list(), scope.sign(key, message), scope.delete(key), vault.wipe()];
    // Handled at once: generate does crypto first, so the others reject while it is still running.
    await Promise.all(calls.map((call) => expect(call).rejects.toMatchObject({ name: 'InvalidStateError' })));
    expect(() => vault.scope('other')).toThrow(expect.objectContaining({ name: 'InvalidStateError' }));
  });

  test('sign rejects data that is not a Uint8Array instead of signing something else', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('ed25519');
    // new Uint8Array('hello') is empty: coercing would sign the empty message and report success.
    for (const data of ['hello', [1, 2, 3], new ArrayBuffer(4), new DataView(new ArrayBuffer(4))]) {
      await expect(scope.sign(key, data as never)).rejects.toThrow(new TypeError('data must be a Uint8Array'));
    }
  });

  test('sign and delete take a KeyInfo: a bare id or a KeyInfo whose type was changed is a TypeError', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('ed25519');
    for (const call of [scope.sign(key.id as never, message), scope.delete(key.id as never), scope.sign(null as never, message)]) {
      await expect(call).rejects.toThrow(new TypeError('key must be a KeyInfo returned by generate() or list()'));
    }
    const retyped = { ...key, type: 'secp256k1' } as KeyInfo;
    await expect(scope.sign(retyped, message)).rejects.toThrow(new TypeError(`Key ${key.id} is not of type secp256k1`));
    expect(await scope.list()).toEqual([key]);
  });

  test('a call in flight when the vault is closed fails with InvalidStateError, not a retryable error', async () => {
    const { vault, scope } = await openVault();
    const key = await scope.generate('ed25519');
    const pending = [scope.generate('ed25519'), scope.generate('secp256k1'), scope.list(), scope.sign(key, message)];
    vault.close();
    await Promise.all(pending.map((call) => expect(call).rejects.toMatchObject({ name: 'InvalidStateError' })));
  });

  test('an unknown key type is a programming error (TypeError), not a VaultError', async () => {
    const { scope } = await openVault();
    await expect(scope.generate('rsa' as never)).rejects.toThrow(new TypeError('Unknown key type: rsa'));
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
    await expectVaultError(vault.scope('other').list(), 'corrupted');
    await expectVaultError(scope.generate('ed25519'), 'corrupted');
    await expectVaultError(scope.sign(key, message), 'corrupted');
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

  test('generate draws the key pair once, before any IndexedDB access; a write redone after a wipe seals that same pair', async () => {
    const { vault, scope } = await openVault();
    await scope.generate('ed25519');
    const generate = vi.spyOn(ed25519, 'generate');
    const original = IDBDatabase.prototype.transaction;
    let wiped = false;
    const transaction = vi.spyOn(IDBDatabase.prototype, 'transaction').mockImplementation(function (this: IDBDatabase, ...args) {
      if (args[1] === 'readwrite' && !wiped) {
        // A wipe queued just before generate's commit: transactions on the same stores run in creation order.
        wiped = true;
        const wipe = original.call(this, ['meta', 'keys'], 'readwrite');
        wipe.objectStore('meta').clear();
        wipe.objectStore('keys').clear();
      }
      return original.apply(this, args);
    });

    const key = await scope.generate('ed25519');
    expect(wiped).toBe(true);
    expect(generate).toHaveBeenCalledTimes(1);
    expect(generate.mock.invocationCallOrder[0]).toBeLessThan(transaction.mock.invocationCallOrder[0]!);
    expect(await vault.scope(SCOPE).list()).toEqual([key]);
  });
});
