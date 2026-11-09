import { ed25519 as edwards } from '@noble/curves/ed25519.js';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { base64url, encode, type Bytes } from '../../src/bytes.ts';
import { Vault } from '../../src/index.ts';
import { keyTypes } from '../../src/key-types.ts';
import { keyAad, keyId } from '../../src/records.ts';
import { generateWrappingKey, importPublicKey, seal, unseal } from '../../src/seal.ts';
import {
  cleanup,
  done,
  expectVaultError,
  flipBit,
  openVault,
  plantKey,
  putKey,
  readAll,
  readHeader,
  readKey,
  replaceKey,
  SCOPE,
  tickingClock,
  types,
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

describe('canonical encoding', () => {
  // Pins the storage format: every key id and AAD is built from these bytes, so they must never change.
  test('encodes the exact v1 bytes: tag, 4-byte big-endian length, data; integers as 8 bytes big-endian', () => {
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
    const rejected = [[1, 2, 3], new Int8Array([1]), new Uint8Array([1]).buffer, -1, 1.5, NaN, null, 2 ** 53, 2 ** 64, Infinity];
    for (const value of rejected) {
      expect(() => encode(value as never)).toThrow(TypeError);
    }
  });

  // UTF-8 can't carry a lone surrogate: TextEncoder writes U+FFFD, so these would collide while IndexedDB keeps them apart.
  test('a string with a lone surrogate is rejected, so it can never share an encoding with its U+FFFD twin', () => {
    expect(new TextEncoder().encode('x\uD800')).toEqual(new TextEncoder().encode('x�'));
    for (const value of ['x\uD800', '\uDC00x', 'a\uDFFF\uD800']) expect(() => encode(value)).toThrow(TypeError);
    expect(() => encode('x�', '🔑')).not.toThrow();
  });
});

describe('encryption at rest', () => {
  test('no private key bytes are stored, for any key type: only ciphertext and a non-extractable root key', async () => {
    // Capture private keys on their way into sealing; the test may export them, Vault never does.
    const wrapKey = vi.spyOn(crypto.subtle, 'wrapKey'); // ed25519: a CryptoKey, exported below
    const scalars: Uint8Array[] = []; // secp256k1: the raw scalar, copied before Vault zeroes it
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementation((params, key, data) => {
      scalars.push(new Uint8Array(data as Uint8Array).slice());
      return encrypt(params, key, data);
    });
    const { scope, name } = await openVault();
    for (const type of types) for (let i = 0; i < 2; i++) await scope.generate(type);

    const seeds = await Promise.all(
      wrapKey.mock.calls.map(async ([, key]) => new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)).slice(-32)),
    );
    expect(seeds).toHaveLength(2);
    expect(scalars).toHaveLength(2);
    for (const secret of [...seeds, ...scalars]) expect(secret.some((byte) => byte !== 0)).toBe(true);

    const { bytes, cryptoKeys } = collect(await readAll(name));
    for (const secret of [...seeds, ...scalars]) for (const stored of bytes) expect(contains(stored, secret)).toBe(false);

    expect(cryptoKeys).toHaveLength(1);
    expect(cryptoKeys[0]).toMatchObject({ type: 'private', extractable: false, usages: ['deriveKey'] });
  });

  test('a value sealed by format v1 still opens: key derivation and cipher parameters are pinned', async () => {
    // Sealed once by the v1 code (in Node) to a test-only recipient key. A change that alters seal and unseal
    // alike (HKDF info, label, salt, IV handling) passes every round trip but fails here.
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
    const privateKey = await crypto.subtle.importKey('pkcs8', bytes(v1.recipientPkcs8), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
    const sealed = { ephemeralPublicKey: bytes(v1.ephemeralPublicKey), iv: bytes(v1.iv), ciphertext: bytes(v1.ciphertext) };

    const cipher = await unseal(privateKey, bytes(v1.recipientSpki), sealed, bytes(v1.aad));
    const plaintext = await crypto.subtle.decrypt(cipher.params, cipher.key, sealed.ciphertext);
    expect(new TextDecoder().decode(plaintext)).toBe('vault v1 seal known answer');
  });

  test.each(types)('decrypting needs the root key: with another private key in its place, sign fails closed (%s)', async (type) => {
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
    { field: 'type', atList: true, edit: (r) => ({ ...r, type: types.find((t) => t !== r.type) }) },
    { field: 'publicKey', atList: true, edit: (r, other) => ({ ...r, publicKey: other.publicKey }) },
    { field: 'createdAt', atList: false, edit: (r) => ({ ...r, createdAt: r.createdAt - 1 }) },
    { field: 'label', atList: false, edit: (r, other) => ({ ...r, label: other.label }) },
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

  test('the edit cases cover every stored field of a labelled key record', async () => {
    const { scope, name } = await openVault();
    const record = await readKey(name, (await scope.generate('ed25519', { label: 'x' })).id);
    const fields = Object.entries(record).flatMap(([k, v]) =>
      k === 'sealed' ? Object.keys(v as object).map((s) => `sealed.${s}`) : [k],
    );
    // `scope` is part of the record's IndexedDB key; moving a record between scopes has its own tests.
    expect(fields.sort()).toEqual([...edits.map((e) => e.field), 'scope'].sort());
  });

  describe.each(types)('%s', (type) => {
    test.each(edits)('editing $field of a key record fails closed', async ({ edit, atList }) => {
      tickingClock();
      const { scope, name } = await openVault();
      const [target, other] = [await scope.generate(type, { label: 'target' }), await scope.generate(type, { label: 'other' })];
      const edited = edit(await readKey(name, target.id), await readKey(name, other.id));
      await replaceKey(name, target.id, edited);

      if (atList) await expectVaultError(scope.list(), 'corrupted');
      else expect((await scope.list()).map((k) => k.id)).toEqual([target.id, other.id]); // not visible without decrypting
      await expectVaultError(scope.sign({ ...target, id: edited.id }, message), 'corrupted');
      await expect(scope.sign(other, message)).resolves.toMatchObject({ type });
    });

    test('a label removed from a key, or added to one stored without it, is listed as stored but sign fails closed', async () => {
      const { scope, name } = await openVault();
      const [labelled, plain] = [await scope.generate(type, { label: 'mine' }), await scope.generate(type)];
      const { label: _, ...stripped } = await readKey(name, labelled.id);
      await replaceKey(name, labelled.id, stripped);
      await replaceKey(name, plain.id, { ...(await readKey(name, plain.id)), label: 'planted' });

      const listed = await scope.list();
      expect(listed.find((k) => k.id === labelled.id)).not.toHaveProperty('label');
      expect(listed.find((k) => k.id === plain.id)).toHaveProperty('label', 'planted');
      await expectVaultError(scope.sign(labelled, message), 'corrupted');
      await expectVaultError(scope.sign(plain, message), 'corrupted');
    });

    test('ciphertexts swapped between two key records fail closed', async () => {
      const { scope, name } = await openVault();
      const [a, b] = [await scope.generate(type), await scope.generate(type)];
      const [ra, rb] = [await readKey(name, a.id), await readKey(name, b.id)];
      await replaceKey(name, a.id, { ...ra, sealed: rb.sealed });
      await replaceKey(name, b.id, { ...rb, sealed: ra.sealed });

      await expectVaultError(scope.sign(a, message), 'corrupted');
      await expectVaultError(scope.sign(b, message), 'corrupted');
    });

    test('a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      const [header, record] = [await readHeader(name), await readKey(name, key.id)];

      // Needs no secret: the wrapping key is public and the associated data is the record's own fields.
      const attacker = await keyTypes[type].generate();
      const sealed = await seal(header.wrappingPublicKey, keyAad(record), attacker.seal);
      await replaceKey(name, key.id, { ...record, sealed });

      const cipher = await unseal(header.protection.privateKey, header.wrappingPublicKey, sealed, keyAad(record));
      await expect(keyTypes[type].sign(sealed.ciphertext, cipher, message)).resolves.toHaveLength(64);
      await expectVaultError(scope.sign(key, message), 'corrupted');
    });

    test('a key record moved to another scope with its id recomputed is listed there, but sign fails closed', async () => {
      const { vault, name } = await openVault();
      const [a, b] = [vault.scope('a'), vault.scope('b')];
      const key = await a.generate(type);
      const record = await readKey(name, key.id, 'a');
      // No secret needed: the id is a hash of public fields. The AAD binds scope and id, so decryption fails.
      const moved = { ...record, scope: 'b', id: await keyId('b', type, record.publicKey) };
      await putKey(name, moved);

      const [listed] = await b.list();
      expect(listed).toMatchObject({ id: moved.id, scope: 'b', type });
      await expectVaultError(b.sign(listed!, message), 'corrupted');
      expect(await a.list()).toEqual([key]);
      await expect(a.sign(key, message)).resolves.toMatchObject({ type });
    });

    test('a key record moved to another scope with its id kept is rejected by list() there', async () => {
      const { vault, name } = await openVault();
      const key = await vault.scope('a').generate(type);
      await putKey(name, { ...(await readKey(name, key.id, 'a')), scope: 'b' });

      await expectVaultError(vault.scope('b').list(), 'corrupted');
      expect(await vault.scope('a').list()).toEqual([key]);
    });
  });

  // Same value, different type: String() or a loose encoding would make these invisible to the id and AAD.
  const retypes: { label: string; edit: (record: any) => any }[] = [
    { label: "v as the string '1'", edit: (r) => ({ ...r, v: '1' }) },
    { label: 'createdAt as a string', edit: (r) => ({ ...r, createdAt: String(r.createdAt) }) },
    { label: 'publicKey as a plain Array', edit: (r) => ({ ...r, publicKey: Array.from(r.publicKey) }) },
    { label: 'publicKey as an Int8Array', edit: (r) => ({ ...r, publicKey: new Int8Array(r.publicKey.buffer) }) },
    { label: 'sealed.iv as a plain Array', edit: (r) => ({ ...r, sealed: { ...r.sealed, iv: Array.from(r.sealed.iv) } }) },
    {
      label: 'sealed.ciphertext as an ArrayBuffer',
      edit: (r) => ({ ...r, sealed: { ...r.sealed, ciphertext: r.sealed.ciphertext.buffer } }),
    },
  ];

  test.each(retypes)('changing a field type without changing its value fails closed at list: $label', async ({ edit }) => {
    const { scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    await replaceKey(name, key.id, edit(await readKey(name, key.id)));

    await expectVaultError(scope.list(), 'corrupted');
    await expectVaultError(scope.sign(key, message), 'corrupted');
  });

  test('a negative createdAt is rejected at list: the canonical encoding has no negative integers', async () => {
    const { scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    await replaceKey(name, key.id, { ...(await readKey(name, key.id)), createdAt: -1 });

    await expectVaultError(scope.list(), 'corrupted');
  });

  test.each(types)('a planted %s key whose public key has the wrong length is rejected at list', async (type) => {
    const { scope, name } = await openVault();
    await scope.generate(type);
    const key = await plantKey(name, type, crypto.getRandomValues(new Uint8Array(31)));

    await expectVaultError(scope.list(), 'corrupted');
    await expectVaultError(scope.sign(key, message), 'corrupted');
  });

  // The first y ≥ 2 whose encoding is a valid point: a public key with its top bytes zero.
  function smallYPoint(): Bytes {
    for (let y = 2; ; y++) {
      const encoded = new Uint8Array(32);
      new DataView(encoded.buffer).setUint32(0, y, true); // little-endian y
      if (edwards.utils.isValidPublicKey(encoded, false)) return encoded;
    }
  }
  const identity = new Uint8Array(32);
  identity[0] = 1;

  // WebKit's own Ed25519 verify kills the page's process on such keys; Vault verifies with noble, in every engine.
  test.each([
    ['the identity point', identity],
    ['a point with a small y', smallYPoint()],
  ])('a planted ed25519 key whose public key is %s is listed like any added key, and sign fails closed', async (_, publicKey) => {
    const { scope, name } = await openVault();
    await scope.generate('ed25519');
    const key = await plantKey(name, 'ed25519', publicKey);

    expect((await scope.list()).map((k) => k.id)).toContain(key.id);
    await expectVaultError(scope.sign(key, message), 'corrupted');
  });

  test('a tampered wrapping public key makes generate fail closed, not with a raw DataError', async () => {
    const { scope, name } = await openVault();
    await scope.generate('ed25519');
    const header = await readHeader(name);
    await writeHeader(name, { ...header, wrappingPublicKey: flipBit(header.wrappingPublicKey) });

    const error = await expectVaultError(scope.generate('secp256k1'), 'corrupted');
    expect(error.cause).toMatchObject({ name: 'DataError' });
  });

  test('an off-curve ephemeral public key is rejected on import, in every engine', async () => {
    const { publicKey } = await generateWrappingKey();
    await expect(importPublicKey(publicKey)).resolves.toBeInstanceOf(CryptoKey);
    // Flipping a bit of the y coordinate leaves the point off the curve.
    await expect(importPublicKey(flipBit(publicKey))).rejects.toMatchObject({ name: 'DataError' });

    const { scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    const record = await readKey(name, key.id);
    const ephemeralPublicKey = flipBit(record.sealed.ephemeralPublicKey);
    await replaceKey(name, key.id, { ...record, sealed: { ...record.sealed, ephemeralPublicKey } });
    const error = await expectVaultError(scope.sign(key, message), 'corrupted');
    expect(error.cause).toMatchObject({ name: 'DataError' });
  });
});

describe('format versioning', () => {
  const versions: [label: string, v: unknown][] = [['2', 2], ["'1' (a string)", '1'], ['true', true], ['missing', undefined]];

  test.each(versions)('a header with format version %s is rejected, not coerced', async (_, v) => {
    const { scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    await writeHeader(name, { ...(await readHeader(name)), v });

    await expectVaultError(scope.list(), 'corrupted');
    await expectVaultError(scope.sign(key, message), 'corrupted');
    await expectVaultError(scope.generate('ed25519'), 'corrupted');
  });

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

  test('an open vault never blocks a newer format, and refuses to work afterwards', async () => {
    const { scope, name } = await openVault();
    await scope.generate('ed25519');

    const newer = indexedDB.open(name, 2); // `done` rejects if this is blocked by the vault's connection
    newer.onupgradeneeded = () => newer.result.createObjectStore('future');
    (await done(newer)).close();

    await expectVaultError(scope.list(), 'incompatible');
  });

  test('a key of a type this build does not know is incompatible, even with fields this build does not know', async () => {
    const { scope, name } = await openVault();
    const key = await scope.generate('ed25519');
    const other = await scope.generate('secp256k1');
    // What a newer build might write: a new type name, its own fields, no sealed private key.
    const { sealed: _, ...rest } = await readKey(name, key.id);
    await replaceKey(name, key.id, { ...rest, type: 'future-type', credentialId: new Uint8Array(16) });

    const error = await expectVaultError(scope.list(), 'incompatible');
    expect(error.message).toBe('Storage holds a key of type future-type, which this build does not know');
    await expectVaultError(scope.sign(key, message), 'incompatible');
    // Keys of known types still sign, and new keys can be added.
    await expect(scope.sign(other, message)).resolves.toMatchObject({ type: 'secp256k1' });
    await expect(scope.generate('ed25519')).resolves.toMatchObject({ type: 'ed25519' });
  });
});
