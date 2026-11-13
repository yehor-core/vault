import { afterEach, describe, expect, expectTypeOf, test, vi } from 'vitest';
import { keyTypes, type AddableKeyTypeName } from '../../src/key-types.ts';
import { Vault, type KeyInfo, type Scope, type Signature, type VaultState } from '../../src/index.ts';
import {
  asSealed,
  cleanup,
  deleteHeader,
  done,
  expectVaultError,
  keyRef,
  keyTypeCases,
  openVault,
  readAll,
  readHeader,
  readKey,
  tickingClock,
  writeHeader,
} from './helpers.ts';

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const message = new TextEncoder().encode('message to sign');

describe.each(keyTypeCases)('$type', ({ type, publicKeyLength, signatureLength, verify }) => {
  describe('keys', () => {
    test('a generated key is listed with its public information', async () => {
      const { scope } = await openVault();
      const before = Date.now();
      const key = await scope.generate(type);

      expect(key.type).toBe(type);
      expect(key.scope).toBe(scope.name);
      expect(key.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(key.publicKey).toHaveLength(publicKeyLength);
      expect(key.createdAt.getTime()).toBeGreaterThanOrEqual(before);
      expect(await scope.list()).toEqual([key]);
    });

    test('a signature verifies under the public key without Vault', async () => {
      const { scope } = await openVault();
      const key = await scope.generate(type);
      const signature = await scope.sign(key, message);

      expect(signature.type).toBe(type);
      expect(signature.bytes).toHaveLength(signatureLength);
      expect(await verify(key.publicKey, signature.bytes, message)).toBe(true);
      expect(await verify(key.publicKey, signature.bytes, new TextEncoder().encode('other'))).toBe(false);
    });

    test('keys survive closing and reopening the vault', async () => {
      const { vault, scope, name } = await openVault();
      const key = await scope.generate(type);
      vault.close();

      const reopened = await Vault.open({ name });
      try {
        const again = reopened.scope(scope.name);
        expect(await again.list()).toEqual([key]);
        const signature = await again.sign(key, message);
        expect(await verify(key.publicKey, signature.bytes, message)).toBe(true);
      } finally {
        reopened.close();
      }
    });

    test('keys are listed oldest first', async () => {
      tickingClock();
      const { scope } = await openVault();
      const keys = [];
      for (let i = 0; i < 4; i++) keys.push(await scope.generate(type));
      expect((await scope.list()).map((k) => k.id)).toEqual(keys.map((k) => k.id));
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

    test('sign and delete take the public information as returned, a structured clone included', async () => {
      tickingClock();
      const { scope } = await openVault();
      const [a, b] = [await scope.generate(type), await scope.generate(type)];
      const [listedA] = await scope.list();
      if (!listedA) throw new Error('no key listed');

      const signature = await scope.sign(structuredClone(asSealed(listedA)), message);
      expect(await verify(a.publicKey, signature.bytes, message)).toBe(true);
      await scope.delete(structuredClone(a));
      expect(await scope.list()).toEqual([b]);
    });

    test('only the id, scope and type of the argument count: edited public key, creation time and label change nothing', async () => {
      tickingClock();
      const { scope } = await openVault();
      const [key, other] = [await scope.generate(type, { label: 'original' }), await scope.generate(type)];
      const edited = { ...key, publicKey: other.publicKey, createdAt: new Date(0), label: 'edited' };

      const signature = await scope.sign(edited, message);
      expect(await verify(key.publicKey, signature.bytes, message)).toBe(true);
      expect(await verify(other.publicKey, signature.bytes, message)).toBe(false);
      expect(await scope.list()).toEqual([key, other]); // the label is still the one given at generate
      await scope.delete(edited);
      expect(await scope.list()).toEqual([other]);
    });

    test('an argument whose type differs from the stored key is a TypeError, and the key is not deleted', async () => {
      const { scope } = await openVault();
      const key = await scope.generate(type);
      const retyped = { ...key, type: 'no-such-type' } as never;

      await expect(scope.sign(retyped, message)).rejects.toThrow(TypeError);
      await expect(scope.delete(retyped)).rejects.toThrow(TypeError);
      expect(await scope.list()).toEqual([key]);
    });

    test('an argument that is not an object with a string id is a TypeError in sign and delete', async () => {
      const { scope } = await openVault();
      const key = await scope.generate(type);
      const malformed = [undefined, null, key.id, 42, {}, { ...key, id: 1 }, { ...key, id: new String(key.id) }];
      for (const arg of malformed) {
        await expect(scope.sign(arg as never, message)).rejects.toThrow(TypeError);
        await expect(scope.delete(arg as never)).rejects.toThrow(TypeError);
      }
      expect(await scope.list()).toEqual([key]);
    });

    test('signing with an unknown key id fails with not-found', async () => {
      const { scope } = await openVault();
      await scope.generate(type);
      const error = await expectVaultError(scope.sign(keyRef(scope, 'no-such-key', type), message), 'not-found');
      expect(error.retryable).toBe(false);
    });

    test('wipe removes every key and the vault header; the next generate starts a new vault', async () => {
      const { vault, scope, name } = await openVault();
      const old = await scope.generate(type);
      const oldHeader = await readHeader(name);

      await vault.wipe();

      expect(await readAll(name)).toEqual({ meta: [], keys: [] });
      expect(await scope.list()).toEqual([]);
      await expectVaultError(scope.sign(old, message), 'not-found');

      const fresh = await scope.generate(type);
      expect(await scope.list()).toEqual([fresh]);
      expect((await readHeader(name)).wrappingPublicKey).not.toEqual(oldHeader.wrappingPublicKey);
    });
  });

  describe('labels', () => {
    test('a label given at generate is stored and carried by the public information; without one there is no label field', async () => {
      tickingClock();
      const { scope, name } = await openVault();
      const labelled = await scope.generate(type, { label: 'Payments' });
      const unlabelled = await scope.generate(type);

      expect(labelled.label).toBe('Payments');
      expect(Object.hasOwn(unlabelled, 'label')).toBe(false);
      expect(await scope.list()).toEqual([labelled, unlabelled]);
      const [listedLabelled, listedUnlabelled] = await scope.list();
      expect(listedLabelled?.label).toBe('Payments');
      expect(Object.hasOwn(listedUnlabelled ?? {}, 'label')).toBe(false);
      expect((await readKey(name, scope.name, labelled.id)).label).toBe('Payments');
      expect(Object.hasOwn(await readKey(name, scope.name, unlabelled.id), 'label')).toBe(false);
      const signature = await scope.sign(labelled, message);
      expect(await verify(labelled.publicKey, signature.bytes, message)).toBe(true);
    });

    test('a malformed label or options argument is a TypeError, thrown before anything is generated or written', async () => {
      const { scope, name } = await openVault();
      const generate = vi.spyOn(keyTypes[type].scheme, 'generate');
      const malformed = ['', 'x'.repeat(257), '\uD800', 'a\uDC00b', 1, null, {}, new String('label')];
      for (const label of malformed) {
        await expect(scope.generate(type, { label: label as never })).rejects.toThrow(TypeError);
      }
      // A string or number where the options belong would otherwise be read as "no label".
      for (const options of ['Payments', 1, null]) {
        await expect(scope.generate(type, options as never)).rejects.toThrow(TypeError);
      }
      expect(generate).not.toHaveBeenCalled();
      expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    });

    test('labels of 1 and 256 code units are kept exactly, and need not be unique', async () => {
      tickingClock();
      const { scope } = await openVault();
      const labels = ['x', 'x'.repeat(256), 'é', 'é', '😀', 'same', 'same'];
      for (const label of labels) await scope.generate(type, { label });
      expect((await scope.list()).map((k) => k.label)).toEqual(labels);
    });
  });

  describe('scopes', () => {
    test('keys generated in one scope are listed only there, and an unused scope lists nothing', async () => {
      const { vault } = await openVault();
      const [a, b] = [vault.scope('app-a'), vault.scope('app-b')];
      const keyA = await a.generate(type);
      const keyB = await b.generate(type);

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
      for (const name of names) await vault.scope(name).generate(type);
      for (const name of names) {
        const scope = vault.scope(name);
        expect(scope.name).toBe(name);
        expect(await scope.list()).toHaveLength(1);
      }
    });

    test('a key passed to another scope is a TypeError in sign and delete: not signed with, not deleted', async () => {
      const { vault } = await openVault();
      const [a, b] = [vault.scope('app-a'), vault.scope('app-b')];
      const key = await a.generate(type);
      const sign = vi.spyOn(keyTypes[type].scheme, 'sign');

      await expect(b.sign(key, message)).rejects.toThrow(TypeError);
      await expect(b.delete(key)).rejects.toThrow(TypeError);
      expect(sign).not.toHaveBeenCalled();
      expect(await a.list()).toEqual([key]);
    });

    test('the id of a key of another scope is not-found by sign and untouched by delete', async () => {
      const { vault } = await openVault();
      const [a, b] = [vault.scope('app-a'), vault.scope('app-b')];
      const key = await a.generate(type);

      const elsewhere = { ...key, scope: b.name }; // the right scope for b, the id of a's key
      await expectVaultError(b.sign(elsewhere, message), 'not-found');
      await b.delete(elsewhere);
      expect(await a.list()).toEqual([key]);
    });

    test('a Scope has no path to its Vault: it can neither wipe nor be retargeted at another scope', async () => {
      const { vault } = await openVault();
      const scope = vault.scope('app-a');
      const key = await scope.generate(type);

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
      await a.generate(type);
      await b.generate(type);
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
      const key = await a.generate(type);
      const pending = [a.list(), b.generate(type), a.sign(key, message)];
      vault.close();

      expect(() => vault.scope('app-c')).toThrow(expect.objectContaining({ name: 'InvalidStateError' }));
      for (const call of [...pending, a.list(), b.list(), a.delete(key)]) {
        await expect(call).rejects.toMatchObject({ name: 'InvalidStateError' });
      }
    });
  });

  describe('lifecycle', () => {
    test('opening and listing write nothing; the first generate creates the vault', async () => {
      const { scope, name } = await openVault();
      expect(await scope.list()).toEqual([]);
      expect(await readAll(name)).toEqual({ meta: [], keys: [] });

      await scope.generate(type);
      await scope.generate(type);
      const { meta, keys } = await readAll(name);
      expect(meta).toHaveLength(1);
      expect(keys).toHaveLength(2);
    });

    // D-40: an application that expects protection checks state() before generate, so an evicted vault isn't refilled unprotected.
    test('state() is empty for a never-used, wiped or deleted vault and unprotected after the first generate', async () => {
      const { vault, scope, name } = await openVault();
      expect(await vault.state()).toBe('empty');

      await scope.generate(type);
      expect(await vault.state()).toBe('unprotected');

      await vault.wipe();
      expect(await vault.state()).toBe('empty');

      await scope.generate(type);
      await done(indexedDB.deleteDatabase(name));
      expect(await vault.state()).toBe('empty');
      expect(await readAll(name)).toEqual({ meta: [], keys: [] }); // state() writes nothing
    });

    // D-12: a deleted header is never read as an empty vault, so state() can't report a protected vault as empty.
    test('state() fails with corrupted, as list does, for key records without a header and for a malformed header', async () => {
      const { vault, scope, name } = await openVault();
      await scope.generate(type);
      const header = await readHeader(name);

      await writeHeader(name, { ...header, v: '1' });
      await expectVaultError(vault.state(), 'corrupted');
      await expectVaultError(scope.list(), 'corrupted');

      await deleteHeader(name);
      await expectVaultError(vault.state(), 'corrupted');
      await expectVaultError(scope.list(), 'corrupted');
    });

    test('state() after close() throws InvalidStateError', async () => {
      const { vault, scope } = await openVault();
      await scope.generate(type);
      vault.close();
      await expect(vault.state()).rejects.toMatchObject({ name: 'InvalidStateError' });
    });

    // Clearing site data, eviction and another tab's deleteDatabase all delete the database under an open vault.
    test('a database deleted while the vault is open is an empty vault: list returns no keys and generate creates a new vault', async () => {
      const { scope, name } = await openVault();
      const old = await scope.generate(type);
      const oldHeader = await readHeader(name);

      await done(indexedDB.deleteDatabase(name)); // never settles, or rejects on `blocked`, if the vault's connection holds it

      expect(await scope.list()).toEqual([]);
      const key = await scope.generate(type);
      expect(await scope.list()).toEqual([key]);
      expect(key.id).not.toBe(old.id);
      expect(await verify(key.publicKey, (await scope.sign(key, message)).bytes, message)).toBe(true);
      const { meta, keys } = await readAll(name);
      expect(meta).toHaveLength(1);
      expect(keys).toHaveLength(1);
      expect((await readHeader(name)).wrappingPublicKey).not.toEqual(oldHeader.wrappingPublicKey);
    });

    test('a generate whose key was sealed before the database was deleted is redone: one key, sealed to the new header', async () => {
      const { scope, name } = await openVault();
      await scope.generate(type);
      const oldHeader = await readHeader(name);
      const generate = keyTypes[type].scheme.generate;
      const spy = vi.spyOn(keyTypes[type].scheme, 'generate').mockImplementationOnce(async () => {
        const generated = await generate();
        return {
          ...generated,
          // Sealed to the old header; the database goes before the write transaction starts.
          seal: async (cipher) => {
            const sealed = await generated.seal(cipher);
            await done(indexedDB.deleteDatabase(name));
            return sealed;
          },
        };
      });

      const key = await scope.generate(type);

      expect(spy).toHaveBeenCalledTimes(2); // the first attempt's write failed its header check
      expect(await scope.list()).toEqual([key]);
      expect(await verify(key.publicKey, (await scope.sign(key, message)).bytes, message)).toBe(true);
      const { meta, keys } = await readAll(name);
      expect(meta).toHaveLength(1);
      expect(keys).toHaveLength(1);
      expect((await readHeader(name)).wrappingPublicKey).not.toEqual(oldHeader.wrappingPublicKey);
    });

    test('a closed vault rejects every call', async () => {
      const { vault, scope } = await openVault();
      const key = await scope.generate(type);
      vault.close();
      const calls = [scope.generate(type), scope.list(), scope.sign(key, message), scope.delete(key), vault.wipe()];
      for (const call of calls) await expect(call).rejects.toMatchObject({ name: 'InvalidStateError' });
    });

    test('sign rejects data that is not a Uint8Array instead of signing something else', async () => {
      const { scope } = await openVault();
      const key = await scope.generate(type);
      // new Uint8Array('hello') is empty: coercing would sign the empty message and report success.
      for (const data of ['hello', [1, 2, 3], new ArrayBuffer(4), new DataView(new ArrayBuffer(4))]) {
        await expect(scope.sign(key, data as never)).rejects.toThrow(new TypeError('data must be a Uint8Array'));
      }
    });

    test('a call in flight when the vault is closed fails with InvalidStateError, not a retryable error', async () => {
      const { vault, scope } = await openVault();
      await scope.generate(type);
      const pending = [scope.generate(type), scope.list(), scope.sign(keyRef(scope, 'any', type), message)];
      vault.close();
      for (const call of pending) await expect(call).rejects.toMatchObject({ name: 'InvalidStateError' });
    });
  });

  describe('errors', () => {
    test('the first generate writes header and key atomically: if the key write fails, no header remains', async () => {
      const { scope, name } = await openVault();
      const add = IDBObjectStore.prototype.add;
      vi.spyOn(IDBObjectStore.prototype, 'add').mockImplementation(function (this: IDBObjectStore, ...args) {
        if (this.name === 'keys') throw new DOMException('simulated quota failure', 'QuotaExceededError');
        return add.apply(this, args);
      });

      await expectVaultError(scope.generate(type), 'unavailable');
      expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    });

    test('a write that aborts at commit, after its body returned, fails as unavailable and stores nothing', async () => {
      const { scope } = await openVault();
      // The same key pair twice gives the same id, so the second add fails asynchronously with ConstraintError.
      // The second seal runs after the first erase; the write fails on the id whatever it seals.
      const pair = await keyTypes[type].scheme.generate();
      vi.spyOn(keyTypes[type].scheme, 'generate').mockResolvedValue(pair);
      const first = await scope.generate(type);

      const error = await expectVaultError(scope.generate(type), 'unavailable');
      expect(error.cause).toMatchObject({ name: 'ConstraintError' });
      expect(await scope.list()).toEqual([first]);
    });

    test('wipe is one transaction: aborted midway, it fails as unavailable and the header and keys remain', async () => {
      const { vault, scope, name } = await openVault();
      const key = await scope.generate(type);
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
      const key = await scope.generate(type);
      await deleteHeader(name);

      await expectVaultError(scope.list(), 'corrupted');
      await expectVaultError(scope.generate(type), 'corrupted');
      await expectVaultError(scope.sign(key, message), 'corrupted');
      expect((await readAll(name)).meta).toEqual([]);

      await vault.wipe();
      await expect(scope.generate(type)).resolves.toMatchObject({ type });
    });

    test('a key generation that keeps failing is retryable unavailable, and stores nothing', async () => {
      const { scope, name } = await openVault();
      vi.spyOn(keyTypes[type].scheme, 'generate').mockRejectedValue(new DOMException('simulated', 'OperationError'));

      const error = await expectVaultError(scope.generate(type), 'unavailable');
      expect(error.cause).toMatchObject({ name: 'OperationError' });
      expect(await readAll(name)).toEqual({ meta: [], keys: [] });
    });

    test('a header stored as undefined is corrupted, not absent and not a retryable failure', async () => {
      const { scope, name } = await openVault();
      await writeHeader(name, undefined);

      await expectVaultError(scope.list(), 'corrupted');
      await expectVaultError(scope.generate(type), 'corrupted');
    });
  });
});

// Both key types by name: the narrowing is static, so each type is written out.
test('the type of a signature follows the type of the key passed to sign', async () => {
  const { scope } = await openVault();
  const [ed, k1] = [await scope.generate('ed25519'), await scope.generate('secp256k1')];
  if (ed.type !== 'ed25519' || k1.type !== 'secp256k1') throw new Error('generate returned another type');
  const signAny = (key: KeyInfo) => scope.sign(key, message); // a parameter: TypeScript can't narrow it

  const [edSignature, k1Signature, anySignature] = [
    await scope.sign(ed, message),
    await scope.sign(k1, message),
    await signAny(k1),
  ];

  expectTypeOf(edSignature).toEqualTypeOf<Signature<'ed25519'>>();
  expectTypeOf(k1Signature).toEqualTypeOf<Signature<'secp256k1'>>();
  expectTypeOf(anySignature).toEqualTypeOf<Signature>();
  expect([edSignature.type, k1Signature.type, anySignature.type]).toEqual(['ed25519', 'secp256k1', 'secp256k1']);
});

// Type-level only: a passkey key needs an authenticator, so nothing here runs (passkey.test.ts signs with one).
test('a passkey KeyInfo carries its credential id, and sign with it returns the passkey assertion', () => {
  expectTypeOf<KeyInfo<'passkey'>>().toEqualTypeOf<{
    readonly id: string;
    readonly scope: string;
    readonly type: 'passkey';
    readonly publicKey: Uint8Array<ArrayBuffer>;
    readonly createdAt: Date;
    readonly label?: string;
    readonly credentialId: Uint8Array<ArrayBuffer>;
  }>();
  expectTypeOf<Scope['generate']>().toBeCallableWith('passkey', { label: 'Payments' });
  expectTypeOf<ReturnType<typeof signPasskey>>().toEqualTypeOf<Promise<Signature<'passkey'>>>();
  expectTypeOf<Signature<'passkey'>>().toEqualTypeOf<{
    readonly type: 'passkey';
    readonly authenticatorData: Uint8Array<ArrayBuffer>;
    readonly clientDataJSON: Uint8Array<ArrayBuffer>;
    readonly signature: Uint8Array<ArrayBuffer>;
  }>();
});

// The sealed members, written out: adding the passkey member changed neither.
test('the KeyInfo and Signature members of sealed key types are unchanged', () => {
  expectTypeOf<KeyInfo<'ed25519'>>().toEqualTypeOf<SealedKeyInfo<'ed25519'>>();
  expectTypeOf<KeyInfo<'secp256k1'>>().toEqualTypeOf<SealedKeyInfo<'secp256k1'>>();
  expectTypeOf<Signature<'ed25519'>>().toEqualTypeOf<SealedSignature<'ed25519'>>();
  expectTypeOf<Signature<'secp256k1'>>().toEqualTypeOf<SealedSignature<'secp256k1'>>();
  // A sealed KeyInfo has no credential id.
  // @ts-expect-error
  void ((key: KeyInfo<'ed25519'>) => key.credentialId);
});

type SealedKeyInfo<T> = {
  readonly id: string;
  readonly scope: string;
  readonly type: T;
  readonly publicKey: Uint8Array<ArrayBuffer>;
  readonly createdAt: Date;
  readonly label?: string;
};
type SealedSignature<T> = { readonly type: T; readonly bytes: Uint8Array<ArrayBuffer> };
const signPasskey = (scope: Scope, key: KeyInfo<'passkey'>) => scope.sign(key, message);

// D-65: one union, so an unprotected vault that is unlocked can't be expressed. locked and unlocked arrive with protect().
test('state() returns exactly empty, unprotected, locked or unlocked', () => {
  expectTypeOf<ReturnType<Vault['state']>>().toEqualTypeOf<Promise<'empty' | 'unprotected' | 'locked' | 'unlocked'>>();
  expectTypeOf<VaultState>().toEqualTypeOf<'empty' | 'unprotected' | 'locked' | 'unlocked'>();
});

// Adding an existing key exists only for key types that can (D-55).
test('add accepts only key types that can add an existing key, and returns that type’s KeyInfo', () => {
  expectTypeOf<AddableKeyTypeName>().toEqualTypeOf<'passkey'>();
  expectTypeOf<Scope['add']>().toBeCallableWith('passkey');
  expectTypeOf<Scope['add']>().toBeCallableWith('passkey', { label: 'Payments' });
  expectTypeOf<ReturnType<typeof addPasskey>>().toEqualTypeOf<Promise<KeyInfo<'passkey'>>>();
  // @ts-expect-error Vault generates every sealed key; none exists elsewhere to add
  void ((scope: Scope) => scope.add('ed25519'));
  // @ts-expect-error likewise
  void ((scope: Scope) => scope.add('secp256k1'));
});
const addPasskey = (scope: Scope) => scope.add('passkey');

// secp256k1's own behaviour. 64 signatures: without low-S, each is high with probability 1/2.
test('every secp256k1 signature is low-S, checked without the curve library', async () => {
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const { scope } = await openVault();
  const key = await scope.generate('secp256k1');
  for (let i = 0; i < 64; i++) {
    const signature = await scope.sign(key, new TextEncoder().encode(`message ${i}`));
    const s = BigInt(`0x${signature.bytes.subarray(32).toHex()}`);
    expect(s > 0n && s <= order >> 1n, `signature ${i}`).toBe(true);
  }
});

describe('lifecycle', () => {
  test('an unknown key type is a programming error (TypeError), not a VaultError', async () => {
    const { scope } = await openVault();
    await expect(scope.generate('no-such-type' as never)).rejects.toThrow(
      new TypeError('Unknown key type: no-such-type'),
    );
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

  test('a database without Vault stores is corrupted, not a retryable failure', async () => {
    const name = `test-${crypto.randomUUID()}`;
    (await done(indexedDB.open(name))).close(); // version 1, no stores: what a bare open(name) leaves
    try {
      await expectVaultError(Vault.open({ name }), 'corrupted');
    } finally {
      await done(indexedDB.deleteDatabase(name));
    }
  });

  // ed25519's own behaviour: WebKit rejects some Ed25519 generations, and the type retries them.
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

describe('ed25519', () => {
  // ed25519's own behaviour: WebKit's crypto.subtle.verify crashes the tab on some public keys, so the
  // verification after signing never reaches it. Signing itself stays in WebCrypto.
  test('signing with an ed25519 key never calls WebCrypto verify', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('ed25519');
    const [subtleVerify, subtleSign] = [vi.spyOn(crypto.subtle, 'verify'), vi.spyOn(crypto.subtle, 'sign')];

    const signature = await scope.sign(key, message);

    expect(subtleSign).toHaveBeenCalledOnce();
    expect(subtleVerify).not.toHaveBeenCalled();
    expect(signature.bytes).toHaveLength(64);
  });
});
