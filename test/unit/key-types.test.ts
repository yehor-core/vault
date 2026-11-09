/// <reference types="vite/client" />
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { Bytes } from '../../src/bytes.ts';
import { ed25519 } from '../../src/ed25519.ts';
import { keyTypes } from '../../src/key-types.ts';
import { generateWrappingKey, seal, unseal } from '../../src/seal.ts';
import { secp256k1 } from '../../src/secp256k1.ts';
import { cleanup, expectVaultError, openVault, plantKey } from './helpers.ts';

afterEach(async () => {
  vi.restoreAllMocks();
  await cleanup();
});

const message = new TextEncoder().encode('message to sign');
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n; // secp256k1 group order
const toBigInt = (bytes: Uint8Array) => BigInt(`0x${bytes.toHex() || '0'}`);
const scalarBytes = (n: bigint) => Uint8Array.fromHex(n.toString(16).padStart(64, '0'));

/** A sealed value and the cipher that opens it, as Vault would hand them to a key type. */
async function sealedWith(plaintext: Bytes) {
  const { publicKey, privateKey } = await generateWrappingKey();
  const aad = new Uint8Array([1]);
  const sealed = await seal(publicKey, aad, ({ key, params }) => crypto.subtle.encrypt(params, key, plaintext));
  return { ciphertext: sealed.ciphertext, cipher: await unseal(privateKey, publicKey, sealed, aad) };
}

describe('secp256k1', () => {
  // RFC 6979 vector for private key 1 (bitcoinjs-lib and trezor-crypto fixtures), and OpenSSL accepts it.
  // It pins every signing choice at once: SHA-256 prehash, deterministic nonce, low-S, r ‖ s.
  test('signs the published RFC 6979 vector exactly: ECDSA over SHA-256(data), deterministic, low-S, r ‖ s', async () => {
    const { ciphertext, cipher } = await sealedWith(scalarBytes(1n));
    const signature = await secp256k1.sign(ciphertext, cipher, new TextEncoder().encode('Satoshi Nakamoto'));
    expect(signature.toHex()).toBe(
      '934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8' +
        '2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5',
    );
  });

  test('every signature Vault returns is low-S, checked without noble', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('secp256k1');
    for (let i = 0; i < 16; i++) {
      const { bytes } = await scope.sign(key, new TextEncoder().encode(`message ${i}`));
      expect(bytes).toHaveLength(64);
      expect(toBigInt(bytes.subarray(32))).toBeLessThanOrEqual(N / 2n);
    }
  });

  test('a public key is stored as a 33-byte compressed point; any other form or an off-curve point is rejected at list', async () => {
    const { scope } = await openVault();
    const key = await scope.generate('secp256k1');
    expect([0x02, 0x03]).toContain(key.publicKey[0]);

    let offCurve = Uint8Array.of(0x02, ...scalarBytes(1n));
    for (let x = 2n; secp256k1.isValidPublicKey(offCurve); x++) offCurve = Uint8Array.of(0x02, ...scalarBytes(x));
    const malformed = [offCurve, Uint8Array.of(0x04, ...key.publicKey.subarray(1)), Uint8Array.of(0x05, ...key.publicKey.subarray(1))];
    for (const publicKey of malformed) {
      const { scope: planted, name } = await openVault();
      await planted.generate('secp256k1');
      await plantKey(name, 'secp256k1', publicKey);
      await expectVaultError(planted.list(), 'corrupted');
    }
  });

  // Anyone can seal any bytes to the public wrapping key; what decrypts must be a valid scalar of exactly 32 bytes.
  const badScalars: [label: string, plaintext: Bytes][] = [
    ['zero', scalarBytes(0n)],
    ['the group order n', scalarBytes(N)],
    ['n + 1', scalarBytes(N + 1n)],
    ['31 bytes', crypto.getRandomValues(new Uint8Array(31))],
    ['33 bytes', crypto.getRandomValues(new Uint8Array(33))],
  ];

  test.each(badScalars)('a planted key whose sealed scalar is %s fails sign closed', async (_, plaintext) => {
    const { scope, name } = await openVault();
    const real = await scope.generate('secp256k1');
    const key = await plantKey(name, 'secp256k1', real.publicKey, ({ key, params }) => crypto.subtle.encrypt(params, key, plaintext));

    expect((await scope.list()).map((k) => k.id)).toContain(key.id);
    await expectVaultError(scope.sign(key, message), 'corrupted');
  });

  test('Vault zeroes the secret buffers it owns: the key-generation seed, the generated scalar and every decrypted scalar', async () => {
    const owned: Uint8Array[] = [];
    let generating = true;
    const getRandomValues = crypto.getRandomValues.bind(crypto);
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(array: T) => {
      // The keygen seed. (noble also draws 48 bytes per signature to blind the nonce inversion: its own, not a secret.)
      if (generating && array instanceof Uint8Array && array.length === 48) owned.push(array);
      return getRandomValues(array as never) as T;
    });
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementation((params, key, data) => {
      owned.push(data as Uint8Array); // the scalar being sealed: the very buffer, not a copy
      return encrypt(params, key, data);
    });
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
      const plaintext = await decrypt(...args);
      owned.push(new Uint8Array(plaintext)); // a view of the buffer Vault receives
      return plaintext;
    });

    const { scope } = await openVault();
    const key = await scope.generate('secp256k1');
    generating = false;
    await scope.sign(key, message);
    expect(owned.map((b) => b.length).sort()).toEqual([32, 32, 48]);
    for (const buffer of owned) expect(buffer.every((byte) => byte === 0)).toBe(true);
  });

  test('a generated key is disposed when generate fails after generating it, and when sign rejects the decrypted value', async () => {
    const disposals: unknown[] = [];
    const generate = secp256k1.generate.bind(secp256k1);
    vi.spyOn(secp256k1, 'generate').mockImplementation(async () => {
      const pair = await generate();
      return { ...pair, dispose: () => (disposals.push(pair), pair.dispose()) };
    });
    const { scope } = await openVault();
    // Fails after the key pair exists: a wrapping public key that won't import.
    vi.spyOn(crypto.subtle, 'importKey').mockRejectedValueOnce(new DOMException('simulated', 'DataError'));
    await expectVaultError(scope.generate('secp256k1'), 'corrupted');
    expect(disposals).toHaveLength(1);

    const decrypted: Uint8Array[] = [];
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
      const plaintext = await decrypt(...args);
      decrypted.push(new Uint8Array(plaintext));
      return plaintext;
    });
    const { ciphertext, cipher } = await sealedWith(Uint8Array.of(...scalarBytes(7n), 0)); // 33 bytes
    await expect(secp256k1.sign(ciphertext, cipher, message)).rejects.toThrow('not a secp256k1 private key');
    expect(decrypted.at(-1)!.every((byte) => byte === 0)).toBe(true);
  });
});

describe('ed25519', () => {
  test('signatures are checked with noble, never with crypto.subtle.verify, which kills WebKit tabs on some planted keys', async () => {
    const verify = vi.spyOn(crypto.subtle, 'verify');
    const { scope } = await openVault();
    const key = await scope.generate('ed25519');
    await expect(scope.sign(key, message)).resolves.toMatchObject({ type: 'ed25519' });
    expect(verify).not.toHaveBeenCalled();
  });

  test('strict RFC 8032 verification: a small-order public key verifies nothing, even with the ZIP-215 identity signature', async () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    // R = identity, S = 0 satisfies the cofactored equation for any message under a small-order key.
    const signature = Uint8Array.of(1, ...new Uint8Array(63));
    expect(await ed25519.verify(identity, signature, message)).toBe(false);
  });
});

describe('the core never branches on key type names', () => {
  // Every file except the registry and the key type modules; new core files are covered automatically.
  const sources = import.meta.glob<string>('../../src/*.ts', { query: '?raw', import: 'default', eager: true });
  const typeModules = new Set(['key-types.ts', ...Object.keys(keyTypes).map((type) => `${type}.ts`)]);
  const core = Object.entries(sources).filter(([path]) => !typeModules.has(path.split('/').pop()!));

  test('no core file mentions a registered key type, so adding one touches only its module and the registry', () => {
    expect(core.length).toBeGreaterThanOrEqual(9);
    for (const [path, source] of core) {
      for (const type of Object.keys(keyTypes)) expect(source.includes(type), `${path} mentions ${type}`).toBe(false);
    }
  });
});
