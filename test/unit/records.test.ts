import { afterEach, describe, expect, test, vi } from 'vitest';
import { Vault } from '../../src/index.ts';
import { keyAad, keyId, parseHeader, parseKeyRecord } from '../../src/records.ts';
import {
  cleanup,
  deleteHeader,
  done,
  expectVaultError,
  keyRef,
  keyTypeCases,
  openVault,
  rawRun,
  readHeader,
  readKey,
  replaceKey,
  writeHeader,
  writeMetaRecord,
} from './helpers.ts';

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const bytes = (hex: string) => Uint8Array.fromHex(hex);

// Produced once by the format-v1 code (in Node). They pin what is stored: a change here is a format change.
// prettier-ignore
const V1 = {
  keyId: 'B6h_TBknJmr8oKLDQBw6xpa3YjhqXWUIrxyA7p0kLNw',
  keyAad:
    '010000000c7661756c742f76312f6b657903000000080000000000000001010000000764656661756c74010000000866697865642d69640100000007656432353531390200000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03000000080000019a5b9ce400',
  record: {
    wrappingPkcs8:
      '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042030bff1a134afcee7dfa051c3d01e08ee05c356a03441498891ca386be04cf09ca14403420004f9205fec50ae1139f642ccb0988617b8378ca4a707b525c8c663c63734700e7ee2d38fd5690d97b5d1fdd3433278b7754f0d2957409c46d1a732c8b5f22262ad',
    wrappingSpki:
      '3059301306072a8648ce3d020106082a8648ce3d03010703420004f9205fec50ae1139f642ccb0988617b8378ca4a707b525c8c663c63734700e7ee2d38fd5690d97b5d1fdd3433278b7754f0d2957409c46d1a732c8b5f22262ad',
    id: 'K5MtTbOM9KLXEdBxAnpSoVnxLXGjAU8w5KeXZoP0QD0',
    publicKey: 'c78452e87daae25cf8ca2618291797748bfbc817df1e3dc55f6ef657a4a01298',
    createdAt: 1762473600000,
    ephemeralPublicKey:
      '3059301306072a8648ce3d020106082a8648ce3d03010703420004783e56e1634ee082bb78c8e2faea31fb8acb025ac0ed96b142c3195464bc92f05c9b1dd557cf591bca00d47d4c7dd1ee00d4037d7d9feb93c47d107c9516bdc6',
    iv: '63a110d85feccc3d7d4f3597',
    ciphertext:
      'd66d7af6042e306b16e7e5d65fd7f41ea56802d4993cdebac128c528a11e27e24f641ec8b9b9e6e5bdba1d973ccb68d8a3bab6b1db1e18cfa2ec1079b657a31f',
  },
};

describe('format v1 regression', () => {
  const fixedPublicKey = Uint8Array.from({ length: 32 }, (_, i) => i);

  // The database name is part of the format: renaming the default would hide every existing user's keys.
  test("the default database name is 'vault'", async () => {
    const vault = await Vault.open();
    try {
      const key = await vault.scope('default').generate('ed25519');
      const stored = await rawRun<any>('vault', ['keys'], (tx) => tx.objectStore('keys').get(['default', key.id]));
      expect(stored?.id).toBe(key.id);
    } finally {
      vault.close();
      await done(indexedDB.deleteDatabase('vault'));
    }
  });

  test('keyId of a fixed input is unchanged', async () => {
    expect(await keyId('default', 'ed25519', fixedPublicKey)).toBe(V1.keyId);
  });

  test('keyAad of fixed fields is unchanged', () => {
    // prettier-ignore
    const fields = { v: 1, scope: 'default', id: 'fixed-id', type: 'ed25519', publicKey: fixedPublicKey, createdAt: 1762473600000 } as const;
    expect(keyAad(fields).toHex()).toBe(V1.keyAad);
  });

  // D-18: a label follows the v1 fields as the tagged parts 'label', label. Derived by hand from the encoding,
  // not by running the code: the v1 AAD above, then 01 00000005 'label', then 01 0000000c 'Paiements é' in UTF-8.
  test('keyAad of a labelled record is the v1 associated data followed by the tagged label', () => {
    // prettier-ignore
    const fields = { v: 1, scope: 'default', id: 'fixed-id', type: 'ed25519', publicKey: fixedPublicKey, createdAt: 1762473600000, label: 'Paiements é' } as const;
    // prettier-ignore
    const expected = V1.keyAad + '01000000056c6162656c' + '010000000c506169656d656e747320c3a9';
    expect(keyAad(fields).toHex()).toBe(expected);
  });

  // S1 had one fixed scope, 'default'; its records live on in the ordinary scope of that name.
  test('a key record written by the v1 code still lists and signs', async () => {
    const { vault, name } = await openVault();
    const scope = vault.scope('default');
    const r = V1.record;
    const root = await crypto.subtle.importKey(
      'pkcs8',
      bytes(r.wrappingPkcs8),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey'],
    );
    const header = { v: 1, wrappingPublicKey: bytes(r.wrappingSpki), protection: { kind: 'none', privateKey: root } };
    const sealed = {
      ephemeralPublicKey: bytes(r.ephemeralPublicKey),
      iv: bytes(r.iv),
      ciphertext: bytes(r.ciphertext),
    };
    const record = {
      v: 1,
      scope: 'default',
      id: r.id,
      type: 'ed25519',
      publicKey: bytes(r.publicKey),
      createdAt: r.createdAt,
      sealed,
    };
    await rawRun(name, ['meta', 'keys'], (tx) => {
      tx.objectStore('meta').put(header, 'header');
      tx.objectStore('keys').put(record);
    });

    expect((await scope.list()).map((k) => k.id)).toEqual([r.id]);
    const data = new TextEncoder().encode('signed by a v1 record');
    const signature = await scope.sign(keyRef(scope, r.id, 'ed25519'), data);
    const publicKey = await crypto.subtle.importKey('raw', bytes(r.publicKey), 'Ed25519', false, ['verify']);
    expect(await crypto.subtle.verify('Ed25519', publicKey, signature.bytes, data)).toBe(true);
  });
});

// Produced once by the S2 code (in Node): a secp256k1 key record in the 'default' scope, its sealed scalar, and the
// signature of a fixed message. Deterministic nonces make the signature a known answer too.
// prettier-ignore
const SECP256K1_RECORD = {
  wrappingPkcs8:
    '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042049eceb65ed5e3c3013d3887db9c476a9cd10aafa257ce9115c24bee49e551a9aa1440342000458b920f0841a41c4cb79e6d20ce1a5b7ac897b7ba85e8a4ebe81742bedd62452f657e3526e8aea0141bb77311dead441639c63bcf5fb915b3992b836cafc23be',
  wrappingSpki:
    '3059301306072a8648ce3d020106082a8648ce3d0301070342000458b920f0841a41c4cb79e6d20ce1a5b7ac897b7ba85e8a4ebe81742bedd62452f657e3526e8aea0141bb77311dead441639c63bcf5fb915b3992b836cafc23be',
  id: 'dLhw1RMiQfGmz1X1xd7Q5x_qAwH9tIyVxWN5-2iDzcI',
  publicKey: '037a99b5f9ce1c6fe48749fc027cb2721884c7b725c017947fb13b881cec2d5dec',
  createdAt: 1762473600000,
  ephemeralPublicKey:
    '3059301306072a8648ce3d020106082a8648ce3d030107034200041c0f45a1721287cae07355453d4481f7000340e9ea4ea00841d2625fc23eb21fdeef6ecfd60f3b49ec208c91d035030bf16fa33b7a774a71d7d3fa75313a1806',
  iv: 'b8c6d3f140ec301f25c10781',
  ciphertext:
    'ae8f76ff944f0e00a126207f5ad9a9f34106cf84dcef853a5d802835f5bdb8eb14fb7d21267374a90726e4ca24e88c2b',
  message: 'signed by a secp256k1 record',
  signature:
    'f7e8aa93a685596778c8be9f60e135423b7e3c2f5b2f6831eb55d1ece434b9280b4d0023b0be48c0b65417564c7d1231a04b5e040e5e8c5b8f8d57cdd096bf5b',
};

describe('format: secp256k1 known answer', () => {
  test('a stored secp256k1 key record lists and gives the expected signature', async () => {
    const { vault, name } = await openVault();
    const scope = vault.scope('default');
    const r = SECP256K1_RECORD;
    const root = await crypto.subtle.importKey(
      'pkcs8',
      bytes(r.wrappingPkcs8),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey'],
    );
    const header = { v: 1, wrappingPublicKey: bytes(r.wrappingSpki), protection: { kind: 'none', privateKey: root } };
    const sealed = {
      ephemeralPublicKey: bytes(r.ephemeralPublicKey),
      iv: bytes(r.iv),
      ciphertext: bytes(r.ciphertext),
    };
    const record = {
      v: 1,
      scope: 'default',
      id: r.id,
      type: 'secp256k1',
      publicKey: bytes(r.publicKey),
      createdAt: r.createdAt,
      sealed,
    };
    await rawRun(name, ['meta', 'keys'], (tx) => {
      tx.objectStore('meta').put(header, 'header');
      tx.objectStore('keys').put(record);
    });

    expect(await scope.list()).toEqual([
      {
        id: r.id,
        scope: 'default',
        type: 'secp256k1',
        publicKey: bytes(r.publicKey),
        createdAt: new Date(r.createdAt),
      },
    ]);
    const signature = await scope.sign(keyRef(scope, r.id, 'secp256k1'), new TextEncoder().encode(r.message));
    expect(signature).toEqual({ type: 'secp256k1', bytes: bytes(r.signature) });
  });
});

/** A real header and key record, as Vault stored them. */
async function storedRecords() {
  const { scope, name } = await openVault();
  const key = await scope.generate('ed25519');
  return { scope, name, header: await readHeader(name), record: await readKey(name, scope.name, key.id) };
}

async function expectCorruptedMessage(parse: () => unknown, what: string) {
  const error = await expectVaultError(Promise.resolve().then(parse), 'corrupted');
  expect(error.message).toBe(`Corrupted storage: ${what}`);
}

describe('strict parsing', () => {
  test('the stored header and key record parse as they are', async () => {
    const { header, record } = await storedRecords();
    expect(parseHeader(header)).toEqual(header);
    expect(await parseKeyRecord(record)).toEqual(record);
  });

  const headerCases: [label: string, what: string, edit: (header: any) => unknown][] = [
    ['not an object', 'header', () => null],
    ["v as '1'", 'header.v', (h) => ({ ...h, v: '1' })],
    ['wrappingPublicKey as a string', 'header.wrappingPublicKey', (h) => ({ ...h, wrappingPublicKey: 'spki' })],
    ['protection missing', 'header.protection', (h) => ({ ...h, protection: null })],
    [
      'unknown protection kind',
      'header.protection.kind',
      (h) => ({ ...h, protection: { ...h.protection, kind: 'passkey' } }),
    ],
    [
      'root not a CryptoKey',
      'header.protection.privateKey',
      (h) => ({ ...h, protection: { ...h.protection, privateKey: {} } }),
    ],
  ];

  test.each(headerCases)('a malformed header field is corrupted and named: %s', async (_, what, edit) => {
    const { header } = await storedRecords();
    await expectCorruptedMessage(() => parseHeader(edit(header)), what);
  });

  const keyCases: [label: string, what: string, edit: (record: any) => unknown][] = [
    ['not an object', 'key', () => 'record'],
    ["v as '1'", 'key.v', (r) => ({ ...r, v: '1' })],
    ['scope as a number', 'key.scope', (r) => ({ ...r, scope: 1 })],
    ['scope empty', 'key.scope', (r) => ({ ...r, scope: '' })],
    ['scope of 1025 code units', 'key.scope', (r) => ({ ...r, scope: 'x'.repeat(1025) })],
    ['scope with a lone surrogate', 'key.scope', (r) => ({ ...r, scope: '\uD800' })],
    ['id as a number', 'key.id', (r) => ({ ...r, id: 1 })],
    ['type empty', 'key.type', (r) => ({ ...r, type: '' })],
    ['type with an uppercase letter', 'key.type', (r) => ({ ...r, type: 'P256' })],
    ['type of 33 characters', 'key.type', (r) => ({ ...r, type: 'x'.repeat(33) })],
    ['type with an underscore', 'key.type', (r) => ({ ...r, type: 'p_256' })],
    ['type as a number', 'key.type', (r) => ({ ...r, type: 256 })],
    ['type missing', 'key.type', (r) => ({ ...r, type: undefined })],
    ["type '__proto__'", 'key.type', (r) => ({ ...r, type: '__proto__' })],
    ["type 'toString'", 'key.type', (r) => ({ ...r, type: 'toString' })],
    ['publicKey as an Array', 'key.publicKey', (r) => ({ ...r, publicKey: Array.from(r.publicKey) })],
    ['publicKey of 31 bytes', 'key.publicKey', (r) => ({ ...r, publicKey: r.publicKey.slice(0, 31) })],
    ['publicKey of 33 bytes', 'key.publicKey', (r) => ({ ...r, publicKey: Uint8Array.of(...r.publicKey, 0) })],
    ['createdAt as a string', 'key.createdAt', (r) => ({ ...r, createdAt: String(r.createdAt) })],
    ['createdAt negative', 'key.createdAt', (r) => ({ ...r, createdAt: -1 })],
    ['label as a number', 'key.label', (r) => ({ ...r, label: 1 })],
    ['label empty', 'key.label', (r) => ({ ...r, label: '' })],
    ['label of 257 code units', 'key.label', (r) => ({ ...r, label: 'x'.repeat(257) })],
    ['label with a lone surrogate', 'key.label', (r) => ({ ...r, label: '\uDC00' })],
    ['label present but undefined', 'key.label', (r) => ({ ...r, label: undefined })],
    ['sealed missing', 'key.sealed', (r) => ({ ...r, sealed: undefined })],
    [
      'ephemeralPublicKey as a string',
      'key.sealed.ephemeralPublicKey',
      (r) => ({ ...r, sealed: { ...r.sealed, ephemeralPublicKey: 'x' } }),
    ],
    ['iv of 11 bytes', 'key.sealed.iv', (r) => ({ ...r, sealed: { ...r.sealed, iv: r.sealed.iv.slice(0, 11) } })],
    [
      'iv of 13 bytes',
      'key.sealed.iv',
      (r) => ({ ...r, sealed: { ...r.sealed, iv: Uint8Array.of(...r.sealed.iv, 0) } }),
    ],
    [
      'ciphertext as an ArrayBuffer',
      'key.sealed.ciphertext',
      (r) => ({ ...r, sealed: { ...r.sealed, ciphertext: r.sealed.ciphertext.buffer } }),
    ],
    ['id of another key', 'key.id does not match its public key', (r) => ({ ...r, id: 'another-id' })],
  ];

  test.each(keyCases)('a malformed key record field is corrupted and named: %s', async (_, what, edit) => {
    const { record } = await storedRecords();
    await expectCorruptedMessage(() => parseKeyRecord(edit(record)), what);
  });

  // 'constructor' is inherited by the registry, not registered in it.
  test.each(['p256', 'x'.repeat(32), 'bls12-381', '0', 'constructor'])(
    'a well-formed key type this build does not know is incompatible, not retryable: %s',
    async (type) => {
      const { record } = await storedRecords();
      const error = await expectVaultError(parseKeyRecord({ ...record, type }), 'incompatible'); // checks retryable: false
      expect(error.message).toBe(`Unknown key type: key.type is ${type}`);
    },
  );

  test('an unknown key type is checked before the rest of the record: its own fields read as incompatible', async () => {
    const { record } = await storedRecords();
    const { publicKey, sealed, ...rest } = record;
    const newer = { ...rest, type: 'p256', point: publicKey, wrapped: sealed, extra: 1 };
    await expectVaultError(parseKeyRecord(newer), 'incompatible');
  });

  const extraFieldCases: [where: string, parse: (header: any, record: any) => unknown][] = [
    ['header', (h) => parseHeader({ ...h, extra: 1 })],
    ['header.protection', (h) => parseHeader({ ...h, protection: { ...h.protection, extra: 1 } })],
    ['key', (_, r) => parseKeyRecord({ ...r, extra: 1 })],
    ['key.sealed', (_, r) => parseKeyRecord({ ...r, sealed: { ...r.sealed, extra: 1 } })],
  ];

  test.each(extraFieldCases)('an unexpected extra field on %s is corrupted', async (where, parse) => {
    const { header, record } = await storedRecords();
    await expectCorruptedMessage(() => parse(header, record), `${where}: unexpected field extra`);
  });

  test('a malformed stored label fails list closed with corrupted, naming the field', async () => {
    const { scope, name, record } = await storedRecords();
    for (const label of [1, '', 'x'.repeat(257), '\uD800', undefined]) {
      await replaceKey(name, scope.name, record.id, { ...record, label });
      const error = await expectVaultError(scope.list(), 'corrupted');
      expect(error.message).toBe('Corrupted storage: key.label');
    }
  });

  test.each(keyTypeCases)(
    'a key of an unknown type is incompatible at list and sign in its scope; other scopes and wipe still work: $type',
    async ({ type }) => {
      const { vault, scope, name } = await openVault();
      const other = vault.scope('other');
      const [key, otherKey] = [await scope.generate(type), await other.generate(type)];
      const record = await readKey(name, scope.name, key.id);
      await replaceKey(name, scope.name, key.id, { ...record, type: 'p256' });

      await expectVaultError(scope.list(), 'incompatible');
      await expectVaultError(scope.sign(key, new Uint8Array(1)), 'incompatible');
      expect(await other.list()).toEqual([otherKey]);
      expect((await other.sign(otherKey, new Uint8Array(1))).type).toBe(type);

      await vault.wipe();
      expect(await scope.list()).toEqual([]);
    },
  );

  test('an extra field fails closed through the API too, for the header and for a key record', async () => {
    const { scope, name, header, record } = await storedRecords();
    await replaceKey(name, scope.name, record.id, { ...record, note: 'not in format v1' });
    await expectVaultError(scope.list(), 'corrupted');

    await replaceKey(name, scope.name, record.id, record);
    await writeHeader(name, { ...header, extra: 1 });
    await expectVaultError(scope.list(), 'corrupted');
  });
});

// The key only gets a vault written; which type it is doesn't matter to these checks.
describe('foreign records', () => {
  const message = new TextEncoder().encode('message');

  // Vault writes only 'header' into meta: anything else is planted, or a format this build doesn't know.
  test.each([
    { header: true, keys: true },
    { header: true, keys: false },
    { header: false, keys: true },
    { header: false, keys: false },
  ])(
    'a record in meta other than the header makes list, generate and sign fail with corrupted, naming it: header $header, keys $keys',
    async ({ header, keys }) => {
      const { scope, name } = await openVault();
      const key = await scope.generate('ed25519');
      if (!keys) await rawRun(name, ['keys'], (tx) => void tx.objectStore('keys').clear());
      if (!header) await deleteHeader(name);
      await writeMetaRecord(name, 'header2', { v: 1 });

      for (const call of [() => scope.list(), () => scope.generate('ed25519'), () => scope.sign(key, message)]) {
        const error = await expectVaultError(call(), 'corrupted');
        expect(error.message).toBe('Corrupted storage: meta: unexpected record "header2"');
      }
    },
  );

  // Each kind of IndexedDB key is named unambiguously: 7 and '7' differ, and bytes don't read as [object ArrayBuffer].
  const keyNames: [key: IDBValidKey, named: string][] = [
    ['7', '"7"'],
    [7, '7'],
    [new Date(0), 'Date 1970-01-01T00:00:00.000Z'],
    [Uint8Array.of(1, 255).buffer, 'bytes 01ff'],
    [['a', 7, ['b']], '["a", 7, ["b"]]'],
  ];
  test.each(keyNames)('a foreign record in meta is named by its key, with the key’s type: %s', async (key, named) => {
    const { scope, name } = await openVault();
    await scope.generate('ed25519');
    await writeMetaRecord(name, key, { v: 1 });
    const error = await expectVaultError(scope.list(), 'corrupted');
    expect(error.message).toBe(`Corrupted storage: meta: unexpected record ${named}`);
  });

  test('wipe recovers a vault with a foreign record in meta; the next generate starts a new vault', async () => {
    const { vault, scope, name } = await openVault();
    await scope.generate('ed25519');
    const oldHeader = await readHeader(name);
    await writeMetaRecord(name, 'extra', { v: 1 });
    await expectVaultError(scope.list(), 'corrupted');

    await vault.wipe();

    expect(await scope.list()).toEqual([]);
    const fresh = await scope.generate('ed25519');
    expect(await scope.list()).toEqual([fresh]);
    expect((await readHeader(name)).wrappingPublicKey).not.toEqual(oldHeader.wrappingPublicKey);
  });

  // Never read, so it can't mislead Vault; rejecting it would leave a vault that wipe can't recover.
  test('an object store that is not Vault’s is ignored: open, list, generate, sign and wipe work as before', async () => {
    const { vault, scope } = await openVault({
      // At Vault's version, with Vault's stores and one more holding a record, as another library could create it.
      // The schema is copied from src/db.ts: if Vault's stores change, this must follow, or Vault rejects them.
      async before(name) {
        const request = indexedDB.open(name, 1);
        request.onupgradeneeded = () => {
          request.result.createObjectStore('meta');
          request.result.createObjectStore('keys', { keyPath: ['scope', 'id'] });
          request.result.createObjectStore('other').add({ v: 1 }, 'header');
        };
        (await done(request)).close();
      },
    });

    expect(await scope.list()).toEqual([]);
    const key = await scope.generate('ed25519');
    expect(await scope.list()).toEqual([key]);
    expect((await scope.sign(key, message)).type).toBe('ed25519');
    await vault.wipe();
    expect(await scope.list()).toEqual([]);
  });
});
