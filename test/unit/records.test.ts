import { afterEach, describe, expect, test, vi } from 'vitest';
import { Vault } from '../../src/index.ts';
import { keyAad, keyId, parseHeader, parseKeyRecord } from '../../src/records.ts';
import { cleanup, done, expectVaultError, openVault, rawRun, readHeader, readKey, replaceKey, SCOPE, writeHeader } from './helpers.ts';

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const bytes = (hex: string) => Uint8Array.fromHex(hex);

// Produced once by the format-v1 code (in Node). They pin what is stored: a change here is a format change.
const V1 = {
  keyId: 'B6h_TBknJmr8oKLDQBw6xpa3YjhqXWUIrxyA7p0kLNw',
  keyAad:
    '010000000c7661756c742f76312f6b657903000000080000000000000001010000000764656661756c74010000000866697865642d69640100000007656432353531390200000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03000000080000019a5b9ce400',
  wrappingPkcs8:
    '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042030bff1a134afcee7dfa051c3d01e08ee05c356a03441498891ca386be04cf09ca14403420004f9205fec50ae1139f642ccb0988617b8378ca4a707b525c8c663c63734700e7ee2d38fd5690d97b5d1fdd3433278b7754f0d2957409c46d1a732c8b5f22262ad',
  wrappingSpki:
    '3059301306072a8648ce3d020106082a8648ce3d03010703420004f9205fec50ae1139f642ccb0988617b8378ca4a707b525c8c663c63734700e7ee2d38fd5690d97b5d1fdd3433278b7754f0d2957409c46d1a732c8b5f22262ad',
  records: {
    ed25519: {
      id: 'K5MtTbOM9KLXEdBxAnpSoVnxLXGjAU8w5KeXZoP0QD0',
      publicKey: 'c78452e87daae25cf8ca2618291797748bfbc817df1e3dc55f6ef657a4a01298',
      createdAt: 1762473600000,
      ephemeralPublicKey:
        '3059301306072a8648ce3d020106082a8648ce3d03010703420004783e56e1634ee082bb78c8e2faea31fb8acb025ac0ed96b142c3195464bc92f05c9b1dd557cf591bca00d47d4c7dd1ee00d4037d7d9feb93c47d107c9516bdc6',
      iv: '63a110d85feccc3d7d4f3597',
      ciphertext:
        'd66d7af6042e306b16e7e5d65fd7f41ea56802d4993cdebac128c528a11e27e24f641ec8b9b9e6e5bdba1d973ccb68d8a3bab6b1db1e18cfa2ec1079b657a31f',
    },
    // Labelled, so it also pins the label's place in the AAD. ECDSA here is deterministic: the signature is pinned too.
    secp256k1: {
      id: 'ymUClbIvuL98yzjoO1Gpl8dUb6NNz71Ji2bCBvdYHjc',
      publicKey: '032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645',
      createdAt: 1762473600000,
      label: 'v1 fixture',
      ephemeralPublicKey:
        '3059301306072a8648ce3d020106082a8648ce3d030107034200047db504e707e3ba046b1fe986615ff298bdf83cec2791828bcc6659e9caef93d6b358b1d2bc339f8ffbba0c322bf71987c2536b04628351773077320e0d04ad34',
      iv: 'dcdb627174d4d4ff48b61f9a',
      ciphertext: '1b3343c87bbbea69c16ea7da8b737d0304887342c802e6d36640953658e16b8a9d571ce74a56fe86141626e53570bc8a',
      signature:
        'd2a2ca22f5555a9d74b8e69f80f134de73fb23156a21d5a95335bef14e51651c10d07e08150943a0bdd71d17875f65db629699b423a49c5276c791dfb7ef8ded',
    },
  },
};

describe('format v1 regression', () => {
  const fixedPublicKey = Uint8Array.from({ length: 32 }, (_, i) => i);
  const fixedFields = { v: 1, scope: 'default', id: 'fixed-id', type: 'ed25519', publicKey: fixedPublicKey, createdAt: 1762473600000 } as const;

  // The database name is part of the format: renaming the default would hide every existing user's keys.
  test("the default database name is 'vault'", async () => {
    const vault = await Vault.open();
    try {
      const key = await vault.scope(SCOPE).generate('ed25519');
      const stored = await rawRun<any>('vault', ['keys'], (tx) => tx.objectStore('keys').get([SCOPE, key.id]));
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
    expect(keyAad(fixedFields).toHex()).toBe(V1.keyAad);
  });

  // Written out from the encoding rules, not by the code: the v1 AAD, then 'label' and the label as tagged strings.
  test('keyAad of fixed labelled fields appends the tagged pair "label", label to the unlabelled AAD', () => {
    const label = 'fixed label'; // 11 bytes
    const expected = V1.keyAad + '01' + '00000005' + '6c6162656c' + '01' + '0000000b' + '6669786564206c6162656c';
    expect(keyAad({ ...fixedFields, label }).toHex()).toBe(expected);
  });

  test.each(Object.entries(V1.records))('a %s key record written by the v1 code still lists and signs', async (type, r) => {
    const { scope, name } = await openVault();
    const root = await crypto.subtle.importKey('pkcs8', bytes(V1.wrappingPkcs8), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
    const header = { v: 1, wrappingPublicKey: bytes(V1.wrappingSpki), protection: { kind: 'none', privateKey: root } };
    const sealed = { ephemeralPublicKey: bytes(r.ephemeralPublicKey), iv: bytes(r.iv), ciphertext: bytes(r.ciphertext) };
    const label = 'label' in r ? { label: r.label } : {};
    const record = { v: 1, scope: SCOPE, id: r.id, type, publicKey: bytes(r.publicKey), createdAt: r.createdAt, ...label, sealed };
    await rawRun(name, ['meta', 'keys'], (tx) => {
      tx.objectStore('meta').put(header, 'header');
      tx.objectStore('keys').put(record);
    });

    const [key] = await scope.list();
    expect(key).toEqual({ id: r.id, scope: SCOPE, type, publicKey: bytes(r.publicKey), createdAt: new Date(r.createdAt), ...label });
    const signature = await scope.sign(key!, new TextEncoder().encode('signed by a v1 record'));
    if ('signature' in r) expect(signature.bytes.toHex()).toBe(r.signature);
    if (type === 'ed25519') {
      const publicKey = await crypto.subtle.importKey('raw', bytes(r.publicKey), 'Ed25519', false, ['verify']);
      expect(await crypto.subtle.verify('Ed25519', publicKey, signature.bytes, new TextEncoder().encode('signed by a v1 record'))).toBe(true);
    }
  });
});

/** A real header and labelled key record, as Vault stored them. */
async function storedRecords() {
  const { vault, scope, name } = await openVault();
  const key = await scope.generate('ed25519', { label: 'stored' });
  return { vault, scope, name, header: await readHeader(name), record: await readKey(name, key.id) };
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
    ['unknown protection kind', 'header.protection.kind', (h) => ({ ...h, protection: { ...h.protection, kind: 'passkey' } })],
    ['root not a CryptoKey', 'header.protection.privateKey', (h) => ({ ...h, protection: { ...h.protection, privateKey: {} } })],
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
    ['scope of 1025 characters', 'key.scope', (r) => ({ ...r, scope: 'x'.repeat(1025) })],
    ['scope with a lone surrogate', 'key.scope', (r) => ({ ...r, scope: 'default\uD800' })],
    ['id as a number', 'key.id', (r) => ({ ...r, id: 1 })],
    ['id with a lone surrogate', 'key.id', (r) => ({ ...r, id: `${r.id}\uDC00` })],
    ['type as a number', 'key.type', (r) => ({ ...r, type: 1 })],
    ["type 'Ed25519' (not a type name's form)", 'key.type', (r) => ({ ...r, type: 'Ed25519' })],
    ["type '__proto__'", 'key.type', (r) => ({ ...r, type: '__proto__' })],
    ["type 'toString'", 'key.type', (r) => ({ ...r, type: 'toString' })],
    ['type of 33 characters', 'key.type', (r) => ({ ...r, type: 'x'.repeat(33) })],
    ['publicKey as an Array', 'key.publicKey', (r) => ({ ...r, publicKey: Array.from(r.publicKey) })],
    ['publicKey of 31 bytes', 'key.publicKey', (r) => ({ ...r, publicKey: r.publicKey.slice(0, 31) })],
    ['publicKey of 33 bytes', 'key.publicKey', (r) => ({ ...r, publicKey: Uint8Array.of(...r.publicKey, 0) })],
    // y = 2^255 - 1 ≥ p: strict RFC 8032 decoding refuses it.
    ['publicKey not a canonical point encoding', 'key.publicKey', (r) => ({ ...r, publicKey: Uint8Array.of(...Array(31).fill(0xff), 0x7f) })],
    ['createdAt as a string', 'key.createdAt', (r) => ({ ...r, createdAt: String(r.createdAt) })],
    ['createdAt negative', 'key.createdAt', (r) => ({ ...r, createdAt: -1 })],
    ['label as a number', 'key.label', (r) => ({ ...r, label: 1 })],
    ['label empty', 'key.label', (r) => ({ ...r, label: '' })],
    ['label of 257 characters', 'key.label', (r) => ({ ...r, label: 'x'.repeat(257) })],
    ['label with a lone surrogate', 'key.label', (r) => ({ ...r, label: 'x\uD800' })],
    ['label stored as undefined (Vault omits it instead)', 'key.label', (r) => ({ ...r, label: undefined })],
    ['sealed missing', 'key.sealed', (r) => ({ ...r, sealed: undefined })],
    ['ephemeralPublicKey as a string', 'key.sealed.ephemeralPublicKey', (r) => ({ ...r, sealed: { ...r.sealed, ephemeralPublicKey: 'x' } })],
    ['iv of 11 bytes', 'key.sealed.iv', (r) => ({ ...r, sealed: { ...r.sealed, iv: r.sealed.iv.slice(0, 11) } })],
    ['iv of 13 bytes', 'key.sealed.iv', (r) => ({ ...r, sealed: { ...r.sealed, iv: Uint8Array.of(...r.sealed.iv, 0) } })],
    ['ciphertext as an ArrayBuffer', 'key.sealed.ciphertext', (r) => ({ ...r, sealed: { ...r.sealed, ciphertext: r.sealed.ciphertext.buffer } })],
    ['id of another key', 'key.id does not match its public key', (r) => ({ ...r, id: 'another-id' })],
  ];

  test.each(keyCases)('a malformed key record field is corrupted and named: %s', async (_, what, edit) => {
    const { record } = await storedRecords();
    await expectCorruptedMessage(() => parseKeyRecord(edit(record)), what);
  });

  // A name of the right form that this build doesn't know was written by a newer build.
  test.each(['rsa', 'constructor', 'future-type', 'x'.repeat(32)])('a key of the unknown type %s is incompatible, not corrupted', async (type) => {
    const { record } = await storedRecords();
    const error = await expectVaultError(parseKeyRecord({ ...record, type }), 'incompatible');
    expect(error.message).toBe(`Storage holds a key of type ${type}, which this build does not know`);
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

  test('an extra field fails closed through the API too, for the header and for a key record', async () => {
    const { scope, name, header, record } = await storedRecords();
    await replaceKey(name, record.id, { ...record, note: 'not in format v1' });
    await expectVaultError(scope.list(), 'corrupted');

    await replaceKey(name, record.id, record);
    await writeHeader(name, { ...header, extra: 1 });
    await expectVaultError(scope.list(), 'corrupted');
  });
});
