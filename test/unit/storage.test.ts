import { afterEach, describe, expect, test, vi } from 'vitest';
import { server } from 'vitest/browser';
import { base64url, encode, type Bytes } from '../../src/bytes.ts';
import { keyTypes, type KeyTypeName } from '../../src/key-types.ts';
import { Vault, type VaultErrorCode } from '../../src/index.ts';
import { keyAad, keyId, type KeyFields } from '../../src/records.ts';
import { generateWrappingKey, importPublicKey, seal, unseal } from '../../src/seal.ts';
import {
  cleanup,
  done,
  expectVaultError,
  flipBit,
  keyTypeCases,
  openVault,
  rawRun,
  readAll,
  readHeader,
  readKey,
  replaceKey,
  tickingClock,
  writeHeader,
} from './helpers.ts';

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const message = new TextEncoder().encode('message to sign');

/** Every Uint8Array and CryptoKey reachable from a structured-cloned value. */
function collect(value: unknown, found = { bytes: [] as Uint8Array[], cryptoKeys: [] as CryptoKey[] }) {
  if (value instanceof Uint8Array) found.bytes.push(value);
  else if (value instanceof ArrayBuffer) found.bytes.push(new Uint8Array(value));
  else if (value instanceof CryptoKey) found.cryptoKeys.push(value);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) collect(v, found);
  return found;
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  for (let i = 0; i + needle.length <= haystack.length; i++) {
    if (needle.every((byte, j) => haystack[i + j] === byte)) return true;
  }
  return false;
}

/** Adds a self-consistent key record with the given public key, as any storage writer can: no secret needed. */
async function plantKey(name: string, scope: string, type: KeyTypeName, publicKey: Bytes): Promise<string> {
  const header = await readHeader(name);
  const fields: KeyFields = {
    v: 1,
    scope,
    id: await keyId(scope, type, publicKey),
    type,
    publicKey,
    createdAt: Date.now(),
  };
  const attacker = await keyTypes[type].generate();
  const sealed = await seal(header.wrappingPublicKey, keyAad(fields), attacker.seal);
  await rawRun(name, ['keys'], (tx) => void tx.objectStore('keys').put({ ...fields, sealed }));
  return fields.id;
}

describe('canonical encoding', () => {
  // Pins the storage format: every key id and AAD is built from these bytes, so they must never change.
  test('encodes the exact v1 bytes: tag, 4-byte big-endian length, data; integers as 8 bytes big-endian', () => {
    // prettier-ignore
    expect(Array.from(encode('a', new Uint8Array([1, 2]), 258, 'é', Number.MAX_SAFE_INTEGER))).toEqual([
      ...[1, 0, 0, 0, 1, 0x61],
      ...[2, 0, 0, 0, 2, 1, 2],
      ...[3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 1, 2],
      ...[1, 0, 0, 0, 2, 0xc3, 0xa9],
      ...[3, 0, 0, 0, 8, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ]);
    expect(Array.from(encode('x'.repeat(300)).subarray(0, 5))).toEqual([1, 0, 0, 0x01, 0x2c]);
    expect(Array.from(encode())).toEqual([]);
  });

  // Key ids are stored, so their text form is part of the format too.
  test('key ids are base64url without padding (RFC 4648 §5)', () => {
    expect(base64url(Uint8Array.of(0xfb, 0xff, 0xfe, 0x00, 0x01))).toBe('-__-AAE');
    expect(base64url(new Uint8Array())).toBe('');
    expect(base64url(new Uint8Array(32).fill(0xff))).toBe('_'.repeat(42) + '8');
  });

  test("each value keeps its type: 123 and '123' differ, and only Uint8Array counts as bytes", () => {
    expect(encode(123)).not.toEqual(encode('123'));
    expect(encode(new Uint8Array([49, 50, 51]))).not.toEqual(encode('123'));
    expect(encode('a', 'bc')).not.toEqual(encode('ab', 'c'));
    // 2 ** 64 matters most: written as 8 bytes it would wrap around and encode exactly like 0.
    const rejected = [
      [1, 2, 3],
      new Int8Array([1]),
      new Uint8Array([1]).buffer,
      -1,
      1.5,
      NaN,
      null,
      2 ** 53,
      2 ** 64,
      Infinity,
    ];
    for (const value of rejected) {
      expect(() => encode(value as never)).toThrow(TypeError);
    }
  });
});

describe('encryption at rest', () => {
  test('a value sealed by format v1 still opens: key derivation and cipher parameters are pinned', async () => {
    // Sealed once by the v1 code (in Node) to a test-only recipient key. A change that alters seal and unseal
    // alike (HKDF info, label, salt, IV handling) passes every round trip but fails here.
    // prettier-ignore
    const v1 = {
      recipientPkcs8:
        '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201edb0959d969d7e98f5d46eb5de08192450b9ecbfa7dc0dd9a0c0b8d3f2cb87aa14403420004f2cd0725ba43ce6c4f05c83a9b8b5419cbf8bd34d15525dfb6d61580fd9e61ef90a50d9f1d15a81545bca1302da58bac232b8534b4913f15b40604d52b8af998',
      recipientSpki:
        '3059301306072a8648ce3d020106082a8648ce3d03010703420004f2cd0725ba43ce6c4f05c83a9b8b5419cbf8bd34d15525dfb6d61580fd9e61ef90a50d9f1d15a81545bca1302da58bac232b8534b4913f15b40604d52b8af998',
      aad: '010000000c7661756c742f76312f6b657903000000080000000000000001010000000764656661756c74010000000766697874757265',
      ephemeralPublicKey:
        '3059301306072a8648ce3d020106082a8648ce3d0301070342000497a722e580798159a265c5a21f4e3abdf929dbc3fd8e02dd127ceeeb07d2140d5f74fb7a3ff1314b7304a9e4f29acc6ae45d32c8da219b61aeaa920ca45193b5',
      iv: '29eb6d32a598be903eadc202',
      ciphertext: 'd55d737b56c3fa8ce5073edb26d288004d5391c63cbd8396372c973b2407e084d870fbe312c65fc813bc',
    };
    const bytes = (hex: string) => Uint8Array.fromHex(hex);
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      bytes(v1.recipientPkcs8),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey'],
    );
    const sealed = {
      ephemeralPublicKey: bytes(v1.ephemeralPublicKey),
      iv: bytes(v1.iv),
      ciphertext: bytes(v1.ciphertext),
    };

    const cipher = await unseal(privateKey, bytes(v1.recipientSpki), sealed, bytes(v1.aad));
    const plaintext = await crypto.subtle.decrypt(cipher.params, cipher.key, sealed.ciphertext);
    expect(new TextDecoder().decode(plaintext)).toBe('vault v1 seal known answer');
  });
});

describe('integrity', () => {
  // ed25519's own points. WebKit 27.2 kills the page's process when Ed25519 verify gets such a key; documented as not protected.
  test.skipIf(server.browser === 'webkit')(
    'a planted key with a degenerate public key is listed like any added key, and sign fails closed',
    async () => {
      const { scope, name } = await openVault();
      await scope.generate('ed25519');
      const identity = new Uint8Array(32);
      identity[0] = 1; // the identity point
      const id = await plantKey(name, scope.name, 'ed25519', identity);

      expect((await scope.list()).map((k) => k.id)).toContain(id);
      await expectVaultError(scope.sign({ id, scope: scope.name, type: 'ed25519' }, message), 'corrupted');
    },
  );
});

describe('format versioning', () => {
  test('a database written by a newer format is rejected with incompatible', async () => {
    const name = `test-${crypto.randomUUID()}`;
    const open = indexedDB.open(name, 2);
    open.onupgradeneeded = () => open.result.createObjectStore('future');
    (await done(open)).close();
    try {
      const error = await expectVaultError(Vault.open({ name }), 'incompatible');
      expect(error.retryable).toBe(false);
    } finally {
      await done(indexedDB.deleteDatabase(name));
    }
  });
});

describe.each(keyTypeCases)('$type', ({ type, signatureLength, invalidPublicKeys, recordPrivateKeys }) => {
  describe('encryption at rest', () => {
    test('no private key bytes are stored: only ciphertext and a non-extractable root key', async () => {
      const privateKeys = recordPrivateKeys();
      const { scope, name } = await openVault();
      await scope.generate(type);
      await scope.generate(type);

      const seeds = await privateKeys();
      expect(seeds).toHaveLength(2);

      const { bytes, cryptoKeys } = collect(await readAll(name));
      for (const seed of seeds) for (const stored of bytes) expect(contains(stored, seed)).toBe(false);

      expect(cryptoKeys).toHaveLength(1);
      expect(cryptoKeys[0]).toMatchObject({ type: 'private', extractable: false, usages: ['deriveKey'] });
    });

    // Wraps each generated key so the test sees when its secrets are erased. `during` runs after generation.
    function watchErase(during: () => Promise<void> = async () => {}): { erased: number }[] {
      const keyType = keyTypes[type];
      const generate = keyType.generate.bind(keyType);
      const pairs: { erased: number }[] = [];
      vi.spyOn(keyType, 'generate').mockImplementation(async () => {
        const pair = await generate();
        const seen = { erased: 0 };
        pairs.push(seen);
        await during();
        const erase = () => {
          seen.erased++;
          pair.erase();
        };
        return { ...pair, erase };
      });
      return pairs;
    }

    test('a generated key has its secrets erased once, after it is stored', async () => {
      const { scope, name } = await openVault();
      const pairs = watchErase();
      const add = IDBObjectStore.prototype.add;
      let storedBeforeErase = false;
      vi.spyOn(IDBObjectStore.prototype, 'add').mockImplementation(function (this: IDBObjectStore, ...args) {
        if (this.name === 'keys') storedBeforeErase = pairs.every((p) => p.erased === 0);
        return add.apply(this, args);
      });

      const key = await scope.generate(type);

      expect(pairs).toEqual([{ erased: 1 }]);
      expect(storedBeforeErase).toBe(true);
      expect(await readKey(name, scope.name, key.id)).toBeDefined();
    });

    const abandoned: {
      label: string;
      arrange: (vault: Vault, name: string) => Promise<(() => Promise<void>) | void>;
      fails: { code: VaultErrorCode } | { name: string };
    }[] = [
      {
        label: 'the id cannot be derived',
        arrange: async () => {
          vi.spyOn(crypto.subtle, 'digest').mockRejectedValueOnce(new DOMException('simulated', 'OperationError'));
        },
        fails: { name: 'OperationError' },
      },
      {
        label: 'sealing fails',
        arrange: async (vault, name) => {
          await vault.scope('other').generate(type);
          const header = await readHeader(name);
          await writeHeader(name, { ...header, wrappingPublicKey: flipBit(header.wrappingPublicKey) });
        },
        fails: { code: 'corrupted' },
      },
      {
        label: 'the write fails',
        arrange: async () => {
          vi.spyOn(IDBObjectStore.prototype, 'add').mockImplementation(() => {
            throw new DOMException('simulated quota failure', 'QuotaExceededError');
          });
        },
        fails: { code: 'unavailable' },
      },
      {
        label: 'the vault keeps changing, so every attempt is abandoned',
        arrange: async (vault, name) => {
          await vault.scope('other').generate(type);
          return async () => {
            const { publicKey, privateKey } = await generateWrappingKey();
            const header = await readHeader(name);
            await writeHeader(name, {
              ...header,
              wrappingPublicKey: publicKey,
              protection: { kind: 'none', privateKey },
            });
          };
        },
        fails: { code: 'unavailable' },
      },
      {
        label: 'the vault is closed',
        arrange: async (vault) => async () => vault.close(),
        fails: { name: 'InvalidStateError' },
      },
    ];

    test.each(abandoned)(
      'a generated key has its secrets erased when generate fails: $label',
      async ({ arrange, fails }) => {
        const { vault, scope, name } = await openVault();
        const during = await arrange(vault, name);
        const pairs = watchErase(during ?? undefined);

        const error = await scope.generate(type).then(
          () => undefined,
          (e: unknown) => e,
        );

        expect(error).toMatchObject(fails);
        expect(pairs.length).toBeGreaterThan(0);
        for (const pair of pairs) expect(pair).toEqual({ erased: 1 });
      },
    );

    test('decrypting needs the root key: with another private key in its place, sign fails closed', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      const header = await readHeader(name);
      const { privateKey } = await generateWrappingKey();
      await writeHeader(name, { ...header, protection: { ...header.protection, privateKey } });

      expect((await readHeader(name)).protection.privateKey).toBeInstanceOf(CryptoKey);
      const error = await expectVaultError(scope.sign(key, message), 'corrupted');
      expect(error.cause).toMatchObject({ name: 'OperationError' }); // AES-GCM authentication failed
    });
  });

  describe('integrity', () => {
    // Each case edits one stored field. `atList` says whether list() can see it (no secret needed)
    // or only sign() does, when the key is decrypted.
    const edits: { field: string; atList: boolean; edit: (record: any, other: any) => any }[] = [
      { field: 'v', atList: true, edit: (r) => ({ ...r, v: 2 }) },
      { field: 'id', atList: true, edit: (r) => ({ ...r, id: base64url(crypto.getRandomValues(new Uint8Array(32))) }) },
      { field: 'type', atList: true, edit: (r) => ({ ...r, type: r.type.toUpperCase() }) }, // registered by no build
      { field: 'publicKey', atList: true, edit: (r, other) => ({ ...r, publicKey: other.publicKey }) },
      { field: 'createdAt', atList: false, edit: (r) => ({ ...r, createdAt: r.createdAt - 1 }) },
      {
        field: 'sealed.ephemeralPublicKey',
        atList: false,
        edit: (r, other) => ({ ...r, sealed: { ...r.sealed, ephemeralPublicKey: other.sealed.ephemeralPublicKey } }),
      },
      { field: 'sealed.iv', atList: false, edit: (r) => ({ ...r, sealed: { ...r.sealed, iv: flipBit(r.sealed.iv) } }) },
      {
        field: 'sealed.ciphertext',
        atList: false,
        edit: (r) => ({ ...r, sealed: { ...r.sealed, ciphertext: flipBit(r.sealed.ciphertext) } }),
      },
    ];

    test('the edit cases cover every stored field of a key record', async () => {
      const { scope, name } = await openVault();
      const record = await readKey(name, scope.name, (await scope.generate(type)).id);
      const fields = Object.entries(record).flatMap(([k, v]) =>
        k === 'sealed' ? Object.keys(v as object).map((s) => `sealed.${s}`) : [k],
      );
      // `scope` is part of the record's IndexedDB key; moving a record between scopes has its own test.
      expect(fields.sort()).toEqual([...edits.map((e) => e.field), 'scope'].sort());
    });

    test.each(edits)('editing $field of a key record fails closed', async ({ edit, atList }) => {
      tickingClock();
      const { scope, name } = await openVault();
      const [target, other] = [await scope.generate(type), await scope.generate(type)];
      const edited = edit(await readKey(name, scope.name, target.id), await readKey(name, scope.name, other.id));
      await replaceKey(name, scope.name, target.id, edited);

      if (atList) await expectVaultError(scope.list(), 'corrupted');
      else expect((await scope.list()).map((k) => k.id)).toEqual([target.id, other.id]); // not visible without decrypting
      await expectVaultError(scope.sign({ ...target, id: edited.id }, message), 'corrupted');
      await expect(scope.sign(other, message)).resolves.toMatchObject({ type });
    });

    // Same value, different type: String() or a loose encoding would make these invisible to the id and AAD.
    const retypes: { label: string; edit: (record: any) => any }[] = [
      { label: "v as the string '1'", edit: (r) => ({ ...r, v: '1' }) },
      { label: 'createdAt as a string', edit: (r) => ({ ...r, createdAt: String(r.createdAt) }) },
      { label: 'publicKey as a plain Array', edit: (r) => ({ ...r, publicKey: Array.from(r.publicKey) }) },
      { label: 'publicKey as an Int8Array', edit: (r) => ({ ...r, publicKey: new Int8Array(r.publicKey.buffer) }) },
      {
        label: 'sealed.iv as a plain Array',
        edit: (r) => ({ ...r, sealed: { ...r.sealed, iv: Array.from(r.sealed.iv) } }),
      },
      {
        label: 'sealed.ciphertext as an ArrayBuffer',
        edit: (r) => ({ ...r, sealed: { ...r.sealed, ciphertext: r.sealed.ciphertext.buffer } }),
      },
    ];

    test.each(retypes)(
      'changing a field type without changing its value fails closed at list: $label',
      async ({ edit }) => {
        const { scope, name } = await openVault();
        const key = await scope.generate(type);
        await replaceKey(name, scope.name, key.id, edit(await readKey(name, scope.name, key.id)));

        await expectVaultError(scope.list(), 'corrupted');
        await expectVaultError(scope.sign(key, message), 'corrupted');
      },
    );

    test('a negative createdAt is rejected at list: the canonical encoding has no negative integers', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      await replaceKey(name, scope.name, key.id, { ...(await readKey(name, scope.name, key.id)), createdAt: -1 });

      await expectVaultError(scope.list(), 'corrupted');
    });

    test('a planted key whose public key is not valid for its type is rejected at list', async () => {
      const { scope, name } = await openVault();
      await scope.generate(type);
      for (const { label, bytes } of invalidPublicKeys) {
        const id = await plantKey(name, scope.name, type, bytes);

        await expect(scope.list(), label).rejects.toMatchObject({ code: 'corrupted' });
        await expect(scope.sign({ id, scope: scope.name, type }, message), label).rejects.toMatchObject({
          code: 'corrupted',
        });
        await rawRun(name, ['keys'], (tx) => void tx.objectStore('keys').delete([scope.name, id]));
      }
    });

    test('a key record moved to another scope fails closed: at list if its id is kept, at sign if it is recomputed', async () => {
      const { vault, name } = await openVault();
      const [from, to] = [vault.scope('app-a'), vault.scope('app-b')];
      const key = await from.generate(type);
      const record = await readKey(name, from.name, key.id);

      // The id binds the scope, so list() sees the move without any secret.
      await replaceKey(name, from.name, key.id, { ...record, scope: to.name });
      await expectVaultError(to.list(), 'corrupted');

      // An id recomputed for the new scope is consistent, so list() can't tell; the AAD binds the scope and id.
      const id = await keyId(to.name, record.type, record.publicKey);
      await replaceKey(name, to.name, key.id, { ...record, scope: to.name, id });
      expect((await to.list()).map((k) => k.id)).toEqual([id]);
      await expectVaultError(to.sign({ ...key, scope: to.name, id }, message), 'corrupted');
      expect(await from.list()).toEqual([]);
    });

    test('ciphertexts swapped between two key records fail closed', async () => {
      const { scope, name } = await openVault();
      const [a, b] = [await scope.generate(type), await scope.generate(type)];
      const [ra, rb] = [await readKey(name, scope.name, a.id), await readKey(name, scope.name, b.id)];
      await replaceKey(name, scope.name, a.id, { ...ra, sealed: rb.sealed });
      await replaceKey(name, scope.name, b.id, { ...rb, sealed: ra.sealed });

      await expectVaultError(scope.sign(a, message), 'corrupted');
      await expectVaultError(scope.sign(b, message), 'corrupted');
    });

    test('a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      const [header, record] = [await readHeader(name), await readKey(name, scope.name, key.id)];

      // Needs no secret: the wrapping key is public and the associated data is the record's own fields.
      const attacker = await keyTypes[type].generate();
      const sealed = await seal(header.wrappingPublicKey, keyAad(record), attacker.seal);
      await replaceKey(name, scope.name, key.id, { ...record, sealed });

      const cipher = await unseal(header.protection.privateKey, header.wrappingPublicKey, sealed, keyAad(record));
      await expect(keyTypes[type].sign(sealed.ciphertext, cipher, message)).resolves.toHaveLength(signatureLength);
      await expectVaultError(scope.sign(key, message), 'corrupted');
    });

    test('a tampered wrapping public key makes generate fail closed, not with a raw DataError', async () => {
      const { scope, name } = await openVault();
      await scope.generate(type);
      const header = await readHeader(name);
      await writeHeader(name, { ...header, wrappingPublicKey: flipBit(header.wrappingPublicKey) });

      const error = await expectVaultError(scope.generate(type), 'corrupted');
      expect(error.cause).toMatchObject({ name: 'DataError' });
    });

    test('an off-curve ephemeral public key is rejected on import, in every engine', async () => {
      const { publicKey } = await generateWrappingKey();
      await expect(importPublicKey(publicKey)).resolves.toBeInstanceOf(CryptoKey);
      // Flipping a bit of the y coordinate leaves the point off the curve.
      await expect(importPublicKey(flipBit(publicKey))).rejects.toMatchObject({ name: 'DataError' });

      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      const record = await readKey(name, scope.name, key.id);
      const ephemeralPublicKey = flipBit(record.sealed.ephemeralPublicKey);
      await replaceKey(name, scope.name, key.id, { ...record, sealed: { ...record.sealed, ephemeralPublicKey } });
      const error = await expectVaultError(scope.sign(key, message), 'corrupted');
      expect(error.cause).toMatchObject({ name: 'DataError' });
    });
  });

  describe('format versioning', () => {
    const versions: [label: string, v: unknown][] = [
      ['2', 2],
      ["'1' (a string)", '1'],
      ['true', true],
      ['missing', undefined],
    ];

    test.each(versions)('a header with format version %s is rejected, not coerced', async (_, v) => {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      await writeHeader(name, { ...(await readHeader(name)), v });

      await expectVaultError(scope.list(), 'corrupted');
      await expectVaultError(scope.sign(key, message), 'corrupted');
      await expectVaultError(scope.generate(type), 'corrupted');
    });

    test('an open vault never blocks a newer format, and refuses to work afterwards', async () => {
      const { scope, name } = await openVault();
      await scope.generate(type);

      const newer = indexedDB.open(name, 2); // `done` rejects if this is blocked by the vault's connection
      newer.onupgradeneeded = () => newer.result.createObjectStore('future');
      (await done(newer)).close();

      await expectVaultError(scope.list(), 'incompatible');
    });
  });
});
