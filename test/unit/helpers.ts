import { secp256k1 } from '@noble/curves/secp256k1.js';
import { expect, vi } from 'vitest';
import { Vault, VaultError, type KeyInfo, type KeyTypeName, type Scope, type VaultErrorCode } from '../../src/index.ts';

/** What the tests know about one key type, independently of Vault's code. */
export interface KeyTypeCase {
  readonly type: KeyTypeName;
  readonly publicKeyLength: number;
  readonly signatureLength: number;
  /** Verifies a signature with code that is not Vault's. */
  verify(
    publicKey: Uint8Array<ArrayBuffer>,
    signature: Uint8Array<ArrayBuffer>,
    data: Uint8Array<ArrayBuffer>,
  ): Promise<boolean>;
  /** Stored public keys that are not valid for this type. */
  readonly invalidPublicKeys: readonly { readonly label: string; readonly bytes: Uint8Array<ArrayBuffer> }[];
  /** Starts recording the private keys Vault generates; the function it returns reads their raw bytes. */
  recordPrivateKeys(): () => Promise<Uint8Array[]>;
}

// The canonical encodings of the eight ed25519 points of small order (the 8-torsion subgroup), as listed in libsodium's small-order blocklist, crypto_core/ed25519/ref10/ed25519_ref10.c.
// prettier-ignore
export const ED25519_SMALL_ORDER_POINTS: [label: string, hex: string][] = [
  ['the identity point (order 1)', '0100000000000000000000000000000000000000000000000000000000000000'],
  ['order 2', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['order 4, x even', '0000000000000000000000000000000000000000000000000000000000000000'],
  ['order 4, x odd', '0000000000000000000000000000000000000000000000000000000000000080'],
  ['order 8, first, x even', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'],
  ['order 8, first, x odd', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'],
  ['order 8, second, x even', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'],
  ['order 8, second, x odd', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85'],
];

// The secp256k1 generator G (SEC 2 §2.4.1), the public key of the scalar 1.
// prettier-ignore
export const SECP256K1_G = Uint8Array.fromHex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
// prettier-ignore
const SECP256K1_G_UNCOMPRESSED = Uint8Array.fromHex('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8');

// The only place tests hold type-specific inputs. Typed by the registry: a new key type fails to compile
// until it has an entry here, and then every per-type test runs for it.
const keyTypeCaseByName: { [T in KeyTypeName]: KeyTypeCase & { readonly type: T } } = {
  ed25519: {
    type: 'ed25519',
    publicKeyLength: 32,
    signatureLength: 64,
    async verify(publicKey, signature, data) {
      const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
      return crypto.subtle.verify('Ed25519', key, signature, data);
    },
    invalidPublicKeys: [
      { label: '31 bytes', bytes: crypto.getRandomValues(new Uint8Array(31)) },
      { label: '33 bytes', bytes: crypto.getRandomValues(new Uint8Array(33)) },
      { label: 'empty', bytes: new Uint8Array() },
      // Non-canonical encodings, which RFC 8032 §5.1.3 rejects and ZIP-215 accepts (little-endian y, sign bit on top).
      // prettier-ignore
      { label: 'y = p + 3, a non-canonical encoding of the point with y = 3', bytes: Uint8Array.fromHex('f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f') },
      // prettier-ignore
      { label: 'x = 0 with the sign bit set', bytes: Uint8Array.fromHex('0100000000000000000000000000000000000000000000000000000000000080') },
      // prettier-ignore
      { label: 'a y with no x', bytes: Uint8Array.fromHex('0200000000000000000000000000000000000000000000000000000000000000') }, // (y² − 1)/(dy² + 1) is no square mod p
    ],
    recordPrivateKeys() {
      // Vault seals an ed25519 key with wrapKey; the test may export it, Vault never does.
      const wrapKey = vi.spyOn(crypto.subtle, 'wrapKey');
      return () =>
        Promise.all(
          wrapKey.mock.calls.map(async ([, key]) =>
            new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)).slice(-32),
          ),
        );
    },
  },
  secp256k1: {
    type: 'secp256k1',
    publicKeyLength: 33,
    signatureLength: 64,
    // noble is not Vault's code. lowS: false, so low-S is proven by its own test, not by every verify.
    async verify(publicKey, signature, data) {
      return secp256k1.verify(signature, data, publicKey, { prehash: true, lowS: false, format: 'compact' });
    },
    invalidPublicKeys: [
      { label: '32 bytes', bytes: SECP256K1_G.slice(1) },
      { label: '34 bytes', bytes: Uint8Array.of(...SECP256K1_G, 0) },
      { label: 'empty', bytes: new Uint8Array() },
      { label: 'uncompressed form', bytes: SECP256K1_G_UNCOMPRESSED },
      { label: 'prefix 0x04 at 33 bytes', bytes: Uint8Array.of(4, ...SECP256K1_G.slice(1)) },
      { label: 'an x with no point', bytes: Uint8Array.of(2, ...new Uint8Array(31), 5) }, // 5³ + 7 is no square mod p
    ],
    recordPrivateKeys() {
      // Vault seals a secp256k1 key by encrypting its raw scalar. Copied at the call: Vault erases it afterwards.
      const encrypt = crypto.subtle.encrypt.bind(crypto.subtle);
      const scalars: Uint8Array[] = [];
      vi.spyOn(crypto.subtle, 'encrypt').mockImplementation(async (algorithm, key, data) => {
        scalars.push(bufferBytes(data).slice());
        return encrypt(algorithm, key, data);
      });
      return async () => scalars;
    },
  },
};

/** The views a BufferSource covers, without copying. */
function bufferBytes(source: BufferSource): Uint8Array {
  return ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    : new Uint8Array(source);
}

/** One case per registered key type: `describe.each(keyTypeCases)`. */
export const keyTypeCases: readonly KeyTypeCase[] = Object.values(keyTypeCaseByName);

/** Date.now() advancing 1 ms per call, so keys never share a creation millisecond. Restored by vi.restoreAllMocks. */
export function tickingClock(): void {
  let now = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => ++now);
}

const cleanups: (() => Promise<void>)[] = [];

/** The scope `openVault` hands out. Not 'default', so code still bound to S1's fixed scope fails the tests. */
export const TEST_SCOPE = 'test';

/**
 * A vault on a fresh, uniquely named database, and its scope TEST_SCOPE; closed and deleted by `cleanup`.
 * `before` gets the database name before Vault first opens it.
 */
export async function openVault(
  options: { before?: (name: string) => Promise<void> } = {},
): Promise<{ vault: Vault; scope: Scope; name: string }> {
  const name = `test-${crypto.randomUUID()}`;
  await options.before?.(name);
  const vault = await Vault.open({ name });
  cleanups.push(async () => {
    vault.close();
    await done(indexedDB.deleteDatabase(name));
  });
  return { vault, scope: vault.scope(TEST_SCOPE), name };
}

/** A KeyInfo naming key `id` of `scope`, for ids no call returned (planted or edited records); Vault reads only id, scope and type. */
export function keyRef(scope: Scope, id: string, type: KeyTypeName): KeyInfo {
  return { id, scope: scope.name, type, publicKey: new Uint8Array(), createdAt: new Date(0) };
}

export async function cleanup(): Promise<void> {
  await Promise.all(cleanups.splice(0).map((fn) => fn()));
}

export async function expectVaultError(promise: Promise<unknown>, code: VaultErrorCode): Promise<VaultError> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(VaultError);
  expect(error).toMatchObject({ code, retryable: code === 'unavailable' }); // only infrastructure faults are worth retrying
  return error as VaultError;
}

// Raw IndexedDB access, independent of the code under test: what a storage writer can do.

type Store = 'meta' | 'keys';

export async function rawRun<T>(
  name: string,
  stores: Store[],
  body: (tx: IDBTransaction) => IDBRequest<T> | void,
): Promise<T> {
  const db = await done(indexedDB.open(name));
  try {
    const tx = db.transaction(stores, 'readwrite');
    const req = body(tx);
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
    });
    return req?.result as T;
  } finally {
    db.close();
  }
}

export const readHeader = (name: string) => rawRun<any>(name, ['meta'], (tx) => tx.objectStore('meta').get('header'));
export const writeHeader = (name: string, header: unknown) =>
  rawRun(name, ['meta'], (tx) => void tx.objectStore('meta').put(header, 'header'));
/** Stores `value` in meta under `key`: a record next to the header, which Vault never writes. */
export const writeMetaRecord = (name: string, key: IDBValidKey, value: unknown) =>
  rawRun(name, ['meta'], (tx) => void tx.objectStore('meta').put(value, key));
export const deleteHeader = (name: string) =>
  rawRun(name, ['meta'], (tx) => void tx.objectStore('meta').delete('header'));
export const readKey = (name: string, scope: string, id: string) =>
  rawRun<any>(name, ['keys'], (tx) => tx.objectStore('keys').get([scope, id]));
export const readAll = async (name: string) => ({
  meta: await rawRun<unknown[]>(name, ['meta'], (tx) => tx.objectStore('meta').getAll()),
  keys: await rawRun<unknown[]>(name, ['keys'], (tx) => tx.objectStore('keys').getAll()),
});

/** Replaces the stored record of key `id` in `scope` with `record` (whose own scope and id may differ). */
export const replaceKey = (name: string, scope: string, id: string, record: object) =>
  rawRun(name, ['keys'], (tx) => {
    tx.objectStore('keys').delete([scope, id]);
    tx.objectStore('keys').put(record);
  });

export function flipBit<T extends Uint8Array>(bytes: T, index = bytes.length - 1): T {
  const copy = bytes.slice() as T;
  const byte = copy[index];
  if (byte === undefined) throw new RangeError(`No byte at index ${index}`);
  copy[index] = byte ^ 1;
  return copy;
}

export function done<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    if (req instanceof IDBOpenDBRequest) req.onblocked = () => reject(new Error('blocked'));
  });
}
