import { afterEach, describe, expect, test, vi } from 'vitest';
import { keyAad, keyId } from '../../src/records.ts';
import { cleanup, openVault, rawRun } from './helpers.ts';

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

  test('keyId of a fixed input is unchanged', async () => {
    expect(await keyId('default', 'ed25519', fixedPublicKey)).toBe(V1.keyId);
  });

  test('keyAad of fixed fields is unchanged', () => {
    const fields = { v: 1, scope: 'default', id: 'fixed-id', type: 'ed25519', publicKey: fixedPublicKey, createdAt: 1762473600000 } as const;
    expect(keyAad(fields).toHex()).toBe(V1.keyAad);
  });

  test('a key record written by the v1 code still lists and signs', async () => {
    const { vault, name } = await openVault();
    const r = V1.record;
    const root = await crypto.subtle.importKey('pkcs8', bytes(r.wrappingPkcs8), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
    const header = { v: 1, wrappingPublicKey: bytes(r.wrappingSpki), protection: { kind: 'none', privateKey: root } };
    const sealed = { ephemeralPublicKey: bytes(r.ephemeralPublicKey), iv: bytes(r.iv), ciphertext: bytes(r.ciphertext) };
    const record = { v: 1, scope: 'default', id: r.id, type: 'ed25519', publicKey: bytes(r.publicKey), createdAt: r.createdAt, sealed };
    await rawRun(name, ['meta', 'keys'], (tx) => {
      tx.objectStore('meta').put(header, 'header');
      tx.objectStore('keys').put(record);
    });

    expect((await vault.list()).map((k) => k.id)).toEqual([r.id]);
    const data = new TextEncoder().encode('signed by a v1 record');
    const signature = await vault.sign(r.id, data);
    const publicKey = await crypto.subtle.importKey('raw', bytes(r.publicKey), 'Ed25519', false, ['verify']);
    expect(await crypto.subtle.verify('Ed25519', publicKey, signature.bytes, data)).toBe(true);
  });
});
