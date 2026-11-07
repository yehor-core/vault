import { afterEach, describe, expect, test, vi } from 'vitest';
import { server } from 'vitest/browser';
import { base64url, encode, type Bytes } from '../../src/bytes.ts';
import { ed25519 } from '../../src/ed25519.ts';
import { Vault } from '../../src/index.ts';
import { keyAad, keyId, parseKeyRecord, type KeyFields } from '../../src/records.ts';
import { generateWrappingKey, importPublicKey, seal, unseal } from '../../src/seal.ts';
import {
  cleanup,
  done,
  expectVaultError,
  flipBit,
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
async function plantKey(name: string, publicKey: Bytes): Promise<string> {
  const header = await readHeader(name);
  const fields: KeyFields = {
    v: 1,
    scope: 'default',
    id: await keyId('default', 'ed25519', publicKey),
    type: 'ed25519',
    publicKey,
    createdAt: Date.now(),
  };
  const attacker = await ed25519.generate();
  const sealed = await seal(header.wrappingPublicKey, keyAad(fields), attacker.seal);
  await rawRun(name, ['keys'], (tx) => void tx.objectStore('keys').put({ ...fields, sealed }));
  return fields.id;
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
    for (const value of [[1, 2, 3], new Int8Array([1]), new Uint8Array([1]).buffer, -1, 1.5, NaN, null]) {
      expect(() => encode(value as never)).toThrow(TypeError);
    }
  });
});

describe('encryption at rest', () => {
  test('no private key bytes are stored: only ciphertext and a non-extractable root key', async () => {
    const wrapKey = vi.spyOn(crypto.subtle, 'wrapKey');
    const { vault, name } = await openVault();
    await vault.generate('ed25519');
    await vault.generate('ed25519');

    // Capture the generated private keys on their way into wrapKey; the test may export them, Vault never does.
    const seeds = await Promise.all(
      wrapKey.mock.calls.map(async ([, key]) => new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)).slice(-32)),
    );
    expect(seeds).toHaveLength(2);

    const { bytes, cryptoKeys } = collect(await readAll(name));
    for (const seed of seeds) for (const stored of bytes) expect(contains(stored, seed)).toBe(false);

    expect(cryptoKeys).toHaveLength(1);
    expect(cryptoKeys[0]).toMatchObject({ type: 'private', extractable: false, usages: ['deriveKey'] });
  });

  test('decrypting needs the root key: with another private key in its place, sign fails closed', async () => {
    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    const header = await readHeader(name);
    const { privateKey } = await generateWrappingKey();
    await writeHeader(name, { ...header, protection: { ...header.protection, privateKey } });

    expect((await readHeader(name)).protection.privateKey).toBeInstanceOf(CryptoKey);
    const error = await expectVaultError(vault.sign(key.id, message), 'corrupted');
    expect(error.cause).toMatchObject({ name: 'OperationError' }); // AES-GCM authentication failed
  });
});

describe('integrity', () => {
  // Each case edits one stored field. `atList` says whether list() can see it (no secret needed)
  // or only sign() does, when the key is decrypted.
  const edits: { field: string; atList: boolean; edit: (record: any, other: any) => any }[] = [
    { field: 'v', atList: true, edit: (r) => ({ ...r, v: 2 }) },
    { field: 'id', atList: true, edit: (r) => ({ ...r, id: base64url(crypto.getRandomValues(new Uint8Array(32))) }) },
    { field: 'type', atList: true, edit: (r) => ({ ...r, type: 'secp256k1' }) },
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
    const { vault, name } = await openVault();
    const record = await readKey(name, (await vault.generate('ed25519')).id);
    const fields = Object.entries(record).flatMap(([k, v]) =>
      k === 'sealed' ? Object.keys(v as object).map((s) => `sealed.${s}`) : [k],
    );
    // `scope` is part of the record's IndexedDB key; moving a record between scopes has its own test.
    expect(fields.sort()).toEqual([...edits.map((e) => e.field), 'scope'].sort());
  });

  test.each(edits)('editing $field of a key record fails closed', async ({ edit, atList }) => {
    tickingClock();
    const { vault, name } = await openVault();
    const [target, other] = [await vault.generate('ed25519'), await vault.generate('ed25519')];
    const edited = edit(await readKey(name, target.id), await readKey(name, other.id));
    await replaceKey(name, target.id, edited);

    if (atList) await expectVaultError(vault.list(), 'corrupted');
    else expect((await vault.list()).map((k) => k.id)).toEqual([target.id, other.id]); // not visible without decrypting
    await expectVaultError(vault.sign(edited.id, message), 'corrupted');
    await expect(vault.sign(other.id, message)).resolves.toMatchObject({ type: 'ed25519' });
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
    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    await replaceKey(name, key.id, edit(await readKey(name, key.id)));

    await expectVaultError(vault.list(), 'corrupted');
    await expectVaultError(vault.sign(key.id, message), 'corrupted');
  });

  test('a negative createdAt is rejected at list: the canonical encoding has no negative integers', async () => {
    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    await replaceKey(name, key.id, { ...(await readKey(name, key.id)), createdAt: -1 });

    await expectVaultError(vault.list(), 'corrupted');
  });

  test('a planted key whose public key has the wrong length is rejected at list', async () => {
    const { vault, name } = await openVault();
    await vault.generate('ed25519');
    const id = await plantKey(name, crypto.getRandomValues(new Uint8Array(31)));

    await expectVaultError(vault.list(), 'corrupted');
    await expectVaultError(vault.sign(id, message), 'corrupted');
  });

  // WebKit 27.2 kills the page's process when Ed25519 verify gets such a key; documented as not protected.
  test.skipIf(server.browser === 'webkit')(
    'a planted key with a degenerate public key is listed like any added key, and sign fails closed',
    async () => {
      const { vault, name } = await openVault();
      await vault.generate('ed25519');
      const identity = new Uint8Array(32);
      identity[0] = 1; // the identity point
      const id = await plantKey(name, identity);

      expect((await vault.list()).map((k) => k.id)).toContain(id);
      await expectVaultError(vault.sign(id, message), 'corrupted');
    },
  );

  test('a key record moved to another scope is rejected there: its id binds the scope', async () => {
    const { vault, name } = await openVault();
    const record = await readKey(name, (await vault.generate('ed25519')).id);
    await expect(parseKeyRecord(record)).resolves.toBeDefined();
    await expectVaultError(parseKeyRecord({ ...record, scope: 'other' }), 'corrupted');
  });

  test('ciphertexts swapped between two key records fail closed', async () => {
    const { vault, name } = await openVault();
    const [a, b] = [await vault.generate('ed25519'), await vault.generate('ed25519')];
    const [ra, rb] = [await readKey(name, a.id), await readKey(name, b.id)];
    await replaceKey(name, a.id, { ...ra, sealed: rb.sealed });
    await replaceKey(name, b.id, { ...rb, sealed: ra.sealed });

    await expectVaultError(vault.sign(a.id, message), 'corrupted');
    await expectVaultError(vault.sign(b.id, message), 'corrupted');
  });

  test('a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used', async () => {
    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    const [header, record] = [await readHeader(name), await readKey(name, key.id)];

    // Needs no secret: the wrapping key is public and the associated data is the record's own fields.
    const attacker = await ed25519.generate();
    const sealed = await seal(header.wrappingPublicKey, keyAad(record), attacker.seal);
    await replaceKey(name, key.id, { ...record, sealed });

    const cipher = await unseal(header.protection.privateKey, header.wrappingPublicKey, sealed, keyAad(record));
    await expect(ed25519.sign(sealed.ciphertext, cipher, message)).resolves.toHaveLength(64);
    await expectVaultError(vault.sign(key.id, message), 'corrupted');
  });

  test('an off-curve ephemeral public key is rejected on import, in every engine', async () => {
    const { publicKey } = await generateWrappingKey();
    await expect(importPublicKey(publicKey)).resolves.toBeInstanceOf(CryptoKey);
    // Flipping a bit of the y coordinate leaves the point off the curve.
    await expect(importPublicKey(flipBit(publicKey))).rejects.toMatchObject({ name: 'DataError' });

    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    const record = await readKey(name, key.id);
    const ephemeralPublicKey = flipBit(record.sealed.ephemeralPublicKey);
    await replaceKey(name, key.id, { ...record, sealed: { ...record.sealed, ephemeralPublicKey } });
    const error = await expectVaultError(vault.sign(key.id, message), 'corrupted');
    expect(error.cause).toMatchObject({ name: 'DataError' });
  });
});

describe('format versioning', () => {
  test.each([2, '1', true, undefined])('a header with format version %s is rejected, not coerced', async (v) => {
    const { vault, name } = await openVault();
    const key = await vault.generate('ed25519');
    await writeHeader(name, { ...(await readHeader(name)), v });

    await expectVaultError(vault.list(), 'corrupted');
    await expectVaultError(vault.sign(key.id, message), 'corrupted');
    await expectVaultError(vault.generate('ed25519'), 'corrupted');
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
    const { vault, name } = await openVault();
    await vault.generate('ed25519');

    const newer = indexedDB.open(name, 2); // `done` rejects if this is blocked by the vault's connection
    newer.onupgradeneeded = () => newer.result.createObjectStore('future');
    (await done(newer)).close();

    await expectVaultError(vault.list(), 'incompatible');
  });
});
