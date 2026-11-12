import { afterEach, describe, expect, test, vi } from 'vitest';
import { base64url, encode, type Bytes } from '../../src/bytes.ts';
import { keyTypes, type KeyTypeName } from '../../src/key-types.ts';
import { Vault, type VaultErrorCode } from '../../src/index.ts';
import { keyAad } from '../../src/key-types/sealed.ts';
import { keyId, type KeyFields } from '../../src/records.ts';
import { generateWrappingKey, importPublicKey, seal, unseal, type Cipher } from '../../src/seal.ts';
import {
  cleanup,
  done,
  ED25519_SMALL_ORDER_POINTS,
  expectVaultError,
  flipBit,
  keyRef,
  keyTypeCases,
  openVault,
  rawRun,
  readAll,
  readHeader,
  readKey,
  replaceKey,
  SECP256K1_G,
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

/**
 * Adds a self-consistent key record with the given public key, as any storage writer can: no secret needed.
 * The sealed private key is `encrypt`'s, or else a fresh key of the type.
 */
async function plantKey(
  name: string,
  scope: string,
  type: KeyTypeName,
  publicKey: Bytes,
  encrypt?: (cipher: Cipher) => Promise<ArrayBuffer>,
): Promise<string> {
  const header = await readHeader(name);
  const fields: KeyFields = {
    v: 1,
    scope,
    id: await keyId(scope, type, publicKey),
    type,
    publicKey,
    createdAt: Date.now(),
  };
  const sealed = await seal(
    header.wrappingPublicKey,
    keyAad(fields),
    encrypt ?? (await keyTypes[type].scheme.generate()).seal,
  );
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
  // ed25519's own behaviour. WebKit 27.2 kills the page's process when its Ed25519 verify gets such a key.
  test.each(ED25519_SMALL_ORDER_POINTS)(
    'a planted ed25519 key whose public key is a small-order point is corrupted at list and sign: %s',
    async (_, hex) => {
      const { scope, name } = await openVault();
      await scope.generate('ed25519');
      const id = await plantKey(name, scope.name, 'ed25519', Uint8Array.fromHex(hex));

      await expectVaultError(scope.list(), 'corrupted');
      await expectVaultError(scope.sign(keyRef(scope, id, 'ed25519'), message), 'corrupted');
    },
  );
});

/** Seals `plaintext` as it stands as a planted key's private key: what a secp256k1 key stores is its raw scalar. */
const sealPlaintext = (plaintext: Bytes) => (cipher: Cipher) =>
  crypto.subtle.encrypt(cipher.params, cipher.key, plaintext);

const isZero = (bytes: Uint8Array) => bytes.every((byte) => byte === 0);

// secp256k1's own behaviour.
describe('secp256k1', () => {
  const one = Uint8Array.fromHex('0000000000000000000000000000000000000000000000000000000000000001');

  // Deterministic ECDSA (RFC 6979) over SHA-256, from bitcoinjs-lib v3.3.2, test/fixtures/ecdsa.json, valid.ecdsa[0]:
  // https://github.com/bitcoinjs/bitcoinjs-lib/blob/v3.3.2/test/fixtures/ecdsa.json (its s is already low).
  test('a published deterministic-ECDSA vector is reproduced exactly', async () => {
    const { scope, name } = await openVault();
    await scope.generate('secp256k1'); // creates the vault: planting needs its public wrapping key
    const id = await plantKey(name, scope.name, 'secp256k1', SECP256K1_G, sealPlaintext(one)); // d = 1, so Q = G
    const data = new TextEncoder().encode('Everything should be made as simple as possible, but not simpler.');

    const signature = await scope.sign(keyRef(scope, id, 'secp256k1'), data);

    // prettier-ignore
    expect(signature.bytes.toHex()).toBe(
      '33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9' +
      '6f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262',
    );
  });

  const invalidScalars: [label: string, scalar: Bytes][] = [
    ['zero', new Uint8Array(32)],
    ['the group order n', Uint8Array.fromHex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')],
    ['above the group order', new Uint8Array(32).fill(0xff)],
    ['31 bytes', one.slice(1)],
    ['33 bytes', Uint8Array.of(0, ...one)], // the value 1, one byte too long
  ];

  test.each(invalidScalars)(
    'a planted sealed value that is not a valid scalar is corrupted at sign: %s',
    async (_, scalar) => {
      const { scope, name } = await openVault();
      await scope.generate('secp256k1');
      const id = await plantKey(name, scope.name, 'secp256k1', SECP256K1_G, sealPlaintext(scalar));

      const error = await expectVaultError(scope.sign(keyRef(scope, id, 'secp256k1'), message), 'corrupted');
      // Vault's own check rejects it, before the curve library or the verify after signing sees it.
      expect(error.cause).toMatchObject({ message: 'The sealed secp256k1 key is not a valid scalar' });
    },
  );

  test('generate erases the seed and the scalar it owns, also when the write fails', async () => {
    const { scope } = await openVault();
    const [getRandomValues, encrypt] = [crypto.getRandomValues.bind(crypto), crypto.subtle.encrypt.bind(crypto.subtle)];
    const seeds: Uint8Array[] = [];
    vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => {
      const filled = getRandomValues(array);
      // The seed is the one 48-byte draw: the IV is 12 bytes, the curve library's blinding 16.
      if (filled instanceof Uint8Array && filled.length === 48) seeds.push(filled);
      return filled;
    });
    const scalars: Uint8Array[] = [];
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementation(async (algorithm, key, data) => {
      if (data instanceof Uint8Array && !isZero(data)) scalars.push(data); // the live buffer, to see it zeroed
      return encrypt(algorithm, key, data);
    });

    await scope.generate('secp256k1');
    vi.spyOn(IDBObjectStore.prototype, 'add').mockImplementation(() => {
      throw new DOMException('simulated quota failure', 'QuotaExceededError');
    });
    await expectVaultError(scope.generate('secp256k1'), 'unavailable');

    expect(seeds).toHaveLength(2);
    expect(scalars).toHaveLength(2);
    for (const buffer of [...seeds, ...scalars]) expect(isZero(buffer)).toBe(true);
  });

  test('sign erases the decrypted scalar, also when it is rejected', async () => {
    const { scope, name } = await openVault();
    const key = await scope.generate('secp256k1');
    const planted = await plantKey(name, scope.name, 'secp256k1', SECP256K1_G, sealPlaintext(Uint8Array.of(0, ...one)));
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    const decrypted: Uint8Array[] = [];
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
      const plaintext = await decrypt(...args);
      decrypted.push(new Uint8Array(plaintext));
      return plaintext;
    });

    await scope.sign(key, message);
    await expectVaultError(scope.sign(keyRef(scope, planted, 'secp256k1'), message), 'corrupted');

    expect(decrypted.map((bytes) => bytes.length)).toEqual([32, 33]);
    for (const buffer of decrypted) expect(isZero(buffer)).toBe(true);
  });
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

// The tamper table (D-34) runs the operations in this order; the ones before the detecting one must succeed.
// generate comes before sign: it shows what a replaced header lets through (D-36).
const OPS = ['list', 'generate', 'sign'] as const;
type Op = (typeof OPS)[number];
const opsBefore = (op: Op) => OPS.slice(0, OPS.indexOf(op));

/** The stored header and two key records of a vault; `foreign` reads another vault database of this origin. */
interface Stored {
  readonly header: any;
  readonly target: any;
  readonly other: any;
  foreign(): Promise<{ header: any; key: any }>;
}
/** What is stored in place of the header and of the two key records; absent means unchanged. */
interface Tampered {
  readonly header?: unknown;
  readonly target?: any;
  readonly other?: any;
}
interface TamperCase {
  readonly record: 'header' | 'key record';
  readonly kind: 'modified' | 'swapped' | 'truncated' | 'malformed';
  readonly what: string;
  readonly detectedBy: Op;
  tamper(stored: Stored): Promise<Tampered>;
}

const headerCase = (
  kind: TamperCase['kind'],
  what: string,
  detectedBy: Op,
  edit: (header: any, stored: Stored) => unknown,
): TamperCase => ({
  record: 'header',
  kind,
  what,
  detectedBy,
  tamper: async (s) => ({ header: await edit(s.header, s) }),
});

const keyCase = (
  kind: TamperCase['kind'],
  what: string,
  detectedBy: Op,
  edit: (record: any, stored: Stored) => any,
): TamperCase => ({
  record: 'key record',
  kind,
  what,
  detectedBy,
  tamper: async (s) => ({ target: await edit(s.target, s) }),
});

function without(object: any, field: string): any {
  const { [field]: _, ...rest } = object;
  return rest;
}

const shorten = (bytes: Uint8Array) => bytes.slice(0, -1);

/** A P-256 key pair of the wrapping kind, made by the writer, not by Vault. */
async function writerKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: CryptoKey }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
  return {
    publicKey: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    privateKey: pair.privateKey,
  };
}

// Each edits one stored field of a key record; `the edit cases cover every stored field` checks the list is whole.
const edits: { field: string; detectedBy: Op; edit: (record: any, other: any) => any }[] = [
  { field: 'v', detectedBy: 'list', edit: (r) => ({ ...r, v: 2 }) },
  {
    field: 'id',
    detectedBy: 'list',
    edit: (r) => ({ ...r, id: base64url(crypto.getRandomValues(new Uint8Array(32))) }),
  },
  { field: 'type', detectedBy: 'list', edit: (r) => ({ ...r, type: r.type.toUpperCase() }) }, // registered by no build
  { field: 'publicKey', detectedBy: 'list', edit: (r, other) => ({ ...r, publicKey: other.publicKey }) },
  { field: 'createdAt', detectedBy: 'sign', edit: (r) => ({ ...r, createdAt: r.createdAt - 1 }) },
  { field: 'label', detectedBy: 'sign', edit: (r) => ({ ...r, label: `${r.label}!` }) },
  {
    field: 'sealed.ephemeralPublicKey',
    detectedBy: 'sign',
    edit: (r, other) => ({ ...r, sealed: { ...r.sealed, ephemeralPublicKey: other.sealed.ephemeralPublicKey } }),
  },
  {
    field: 'sealed.iv',
    detectedBy: 'sign',
    edit: (r) => ({ ...r, sealed: { ...r.sealed, iv: flipBit(r.sealed.iv) } }),
  },
  {
    field: 'sealed.ciphertext',
    detectedBy: 'sign',
    edit: (r) => ({ ...r, sealed: { ...r.sealed, ciphertext: flipBit(r.sealed.ciphertext) } }),
  },
];

const cases: TamperCase[] = [
  headerCase('modified', 'v is 2', 'list', (h) => ({ ...h, v: 2 })),
  headerCase('modified', 'another protection kind', 'list', (h) => ({
    ...h,
    protection: { ...h.protection, kind: 'passkey' },
  })),
  headerCase('modified', 'a bit of the wrapping public key flipped, off the curve', 'generate', (h) => ({
    ...h,
    wrappingPublicKey: flipBit(h.wrappingPublicKey),
  })),
  // D-36: generate seals the new key to the writer's public key; existing keys no longer open.
  headerCase('modified', 'a wrapping public key of the writer', 'sign', async (h) => ({
    ...h,
    wrappingPublicKey: (await writerKeyPair()).publicKey,
  })),
  headerCase('modified', 'a wrapping public key on another curve, P-384', 'generate', async (h) => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveKey']);
    return { ...h, wrappingPublicKey: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)) };
  }),
  headerCase('modified', 'a root private key of the writer', 'sign', async (h) => ({
    ...h,
    protection: { ...h.protection, privateKey: (await writerKeyPair()).privateKey },
  })),
  headerCase(
    'swapped',
    'the header of another vault database of this origin',
    'sign',
    async (_, s) => (await s.foreign()).header,
  ),
  headerCase('truncated', 'the wrapping public key one byte short', 'generate', (h) => ({
    ...h,
    wrappingPublicKey: shorten(h.wrappingPublicKey),
  })),
  ...['v', 'wrappingPublicKey', 'protection'].map((field) =>
    headerCase('truncated', `${field} removed`, 'list', (h) => without(h, field)),
  ),
  ...['kind', 'privateKey'].map((field) =>
    headerCase('truncated', `protection.${field} removed`, 'list', (h) => ({
      ...h,
      protection: without(h.protection, field),
    })),
  ),
  headerCase('malformed', 'null, not an object', 'list', () => null),
  headerCase('malformed', 'the wrapping public key as a plain Array', 'list', (h) => ({
    ...h,
    wrappingPublicKey: Array.from(h.wrappingPublicKey),
  })),
  headerCase('malformed', 'the root private key not a CryptoKey', 'list', (h) => ({
    ...h,
    protection: { ...h.protection, privateKey: {} },
  })),
  headerCase('malformed', 'the root private key an AES key', 'sign', async (h) => ({
    ...h,
    protection: {
      ...h.protection,
      privateKey: await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']),
    },
  })),
  headerCase('malformed', 'an extra field', 'list', (h) => ({ ...h, extra: 1 })),

  ...edits.map(({ field, detectedBy, edit }) => keyCase('modified', field, detectedBy, (r, s) => edit(r, s.other))),
  keyCase('modified', 'type, another registered key type', 'list', (r) => ({
    ...r,
    type: keyTypeCases.find((c) => c.type !== r.type)?.type,
  })),
  keyCase(
    'swapped',
    'the key record of another vault database of this origin',
    'sign',
    async (_, s) => (await s.foreign()).key,
  ),
  {
    record: 'key record',
    kind: 'swapped',
    what: 'contents exchanged with another key record, scope and id kept',
    detectedBy: 'list',
    tamper: async (s) => ({ target: { ...s.other, id: s.target.id }, other: { ...s.target, id: s.other.id } }),
  },
  {
    record: 'key record',
    kind: 'swapped',
    what: 'sealed parts exchanged with another key record',
    detectedBy: 'sign',
    tamper: async (s) => ({
      target: { ...s.target, sealed: s.other.sealed },
      other: { ...s.other, sealed: s.target.sealed },
    }),
  },
  keyCase('truncated', 'publicKey one byte short', 'list', (r) => ({ ...r, publicKey: shorten(r.publicKey) })),
  // Only the IV has a fixed length list() checks; a short ephemeral key or ciphertext fails to open at sign.
  ...['ephemeralPublicKey', 'iv', 'ciphertext'].map((field) =>
    keyCase('truncated', `sealed.${field} one byte short`, field === 'iv' ? 'list' : 'sign', (r) => ({
      ...r,
      sealed: { ...r.sealed, [field]: shorten(r.sealed[field]) },
    })),
  ),
  // scope and id make up the record's IndexedDB key: a record without them can't be stored.
  ...['v', 'type', 'publicKey', 'createdAt', 'sealed'].map((field) =>
    keyCase('truncated', `${field} removed`, 'list', (r) => without(r, field)),
  ),
  keyCase('truncated', 'label removed', 'sign', (r) => without(r, 'label')),
  ...['ephemeralPublicKey', 'iv', 'ciphertext'].map((field) =>
    keyCase('truncated', `sealed.${field} removed`, 'list', (r) => ({ ...r, sealed: without(r.sealed, field) })),
  ),
  keyCase('malformed', 'createdAt as a string', 'list', (r) => ({ ...r, createdAt: String(r.createdAt) })),
  keyCase('malformed', 'sealed.iv as a plain Array', 'list', (r) => ({
    ...r,
    sealed: { ...r.sealed, iv: Array.from(r.sealed.iv) },
  })),
  keyCase('malformed', 'sealed null, not an object', 'list', (r) => ({ ...r, sealed: null })),
  keyCase('malformed', 'an empty label', 'list', (r) => ({ ...r, label: '' })),
  keyCase('malformed', 'an extra field', 'list', (r) => ({ ...r, extra: 1 })),
];
// Titled through %s: vitest cuts a $field value at 40 characters, which would drop the verdict.
const tamperCases = cases.map((c) => [`${c.record} ${c.kind}, ${c.what}; ${verdict(c.detectedBy)}`, c] as const);

function verdict(detectedBy: Op): string {
  const missed = opsBefore(detectedBy);
  return missed.length === 0
    ? `corrupted at ${detectedBy}`
    : `not detected by ${missed.join(' or ')}, corrupted at ${detectedBy}`;
}

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
      const keyType = keyTypes[type].scheme;
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

  describe('tamper table', () => {
    /** Another vault database of this origin, with one key in the same scope name. */
    async function foreignVault(): Promise<{ header: any; key: any }> {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      return { header: await readHeader(name), key: await readKey(name, scope.name, key.id) };
    }

    test.each(tamperCases)(
      'a bad record is corrupted at the operation the table names: %s',
      async (_, { record, tamper, detectedBy }) => {
        const { scope, name } = await openVault();
        const [target, other] = [await scope.generate(type, { label: 'target' }), await scope.generate(type)];
        const tampered = await tamper({
          header: await readHeader(name),
          target: await readKey(name, scope.name, target.id),
          other: await readKey(name, scope.name, other.id),
          foreign: foreignVault,
        });
        if (tampered.header !== undefined) await writeHeader(name, tampered.header);
        if (tampered.target) await replaceKey(name, scope.name, target.id, tampered.target);
        if (tampered.other) await replaceKey(name, scope.name, other.id, tampered.other);

        const run: Record<Op, () => Promise<unknown>> = {
          list: () => scope.list(),
          generate: () => scope.generate(type),
          sign: () => scope.sign({ ...target, id: tampered.target?.id ?? target.id }, message),
        };
        for (const op of opsBefore(detectedBy)) await run[op](); // not detected: exempt from break-check
        await expectVaultError(run[detectedBy](), 'corrupted');
        // A key record's tampering stays with the records it touched: the other key signs unless it was swapped too.
        if (record === 'key record') {
          if (tampered.other) await expectVaultError(scope.sign(other, message), 'corrupted');
          else await expect(scope.sign(other, message)).resolves.toMatchObject({ type });
        }
      },
    );
  });

  describe('integrity', () => {
    test('the edit cases cover every stored field of a key record', async () => {
      const { scope, name } = await openVault();
      const record = await readKey(name, scope.name, (await scope.generate(type, { label: 'target' })).id);
      const fields = Object.entries(record).flatMap(([k, v]) =>
        k === 'sealed' ? Object.keys(v as object).map((s) => `sealed.${s}`) : [k],
      );
      // `scope` is part of the record's IndexedDB key; moving a record between scopes has its own test.
      expect(fields.sort()).toEqual([...edits.map((e) => e.field), 'scope'].sort());
    });

    // D-18: list() reads no secret, so it shows an edited label; only sign() can detect the edit.
    test('a stored label edited, added or removed makes sign fail with corrupted, and list shows the stored label', async () => {
      tickingClock();
      const { scope, name } = await openVault();
      const [labelled, unlabelled, kept] = [
        await scope.generate(type, { label: 'Payments' }),
        await scope.generate(type),
        await scope.generate(type, { label: 'kept' }),
      ];
      const stored = await readKey(name, scope.name, labelled.id);
      await replaceKey(name, scope.name, labelled.id, { ...stored, label: 'Payroll' });
      expect((await scope.list()).map((k) => k.label)).toEqual(['Payroll', undefined, 'kept']);
      await expectVaultError(scope.sign(labelled, message), 'corrupted');

      const { label: _, ...removed } = stored;
      await replaceKey(name, scope.name, labelled.id, removed);
      await expectVaultError(scope.sign(labelled, message), 'corrupted');

      const added = { ...(await readKey(name, scope.name, unlabelled.id)), label: 'Payments' };
      await replaceKey(name, scope.name, unlabelled.id, added);
      await expectVaultError(scope.sign(unlabelled, message), 'corrupted');

      await expect(scope.sign(kept, message)).resolves.toMatchObject({ type });
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
        await expect(scope.sign(keyRef(scope, id, type), message), label).rejects.toMatchObject({
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

    test('delete removes a record whose stored type was tampered with', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      await replaceKey(name, scope.name, key.id, { ...(await readKey(name, scope.name, key.id)), type: 'TAMPERED' });

      await scope.delete(key);
      expect((await readAll(name)).keys).toEqual([]);
    });

    test('a key an attacker sealed to the public wrapping key decrypts, but is rejected instead of used', async () => {
      const { scope, name } = await openVault();
      const key = await scope.generate(type);
      const [header, record] = [await readHeader(name), await readKey(name, scope.name, key.id)];

      // Needs no secret: the wrapping key is public and the associated data is the record's own fields.
      const attacker = await keyTypes[type].scheme.generate();
      const sealed = await seal(header.wrappingPublicKey, keyAad(record), attacker.seal);
      await replaceKey(name, scope.name, key.id, { ...record, sealed });

      const cipher = await unseal(header.protection.privateKey, header.wrappingPublicKey, sealed, keyAad(record));
      await expect(keyTypes[type].scheme.sign(sealed.ciphertext, cipher, message)).resolves.toHaveLength(
        signatureLength,
      );
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
