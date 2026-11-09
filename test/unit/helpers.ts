import { secp256k1 } from '@noble/curves/secp256k1.js';
import { expect, vi } from 'vitest';
import { Vault, VaultError, type KeyInfo, type Scope, type Signature, type VaultErrorCode } from '../../src/index.ts';
import type { Bytes } from '../../src/bytes.ts';
import { keyTypes, type GeneratedKey, type KeyTypeName } from '../../src/key-types.ts';
import { keyAad, keyId, type KeyFields } from '../../src/records.ts';
import { seal } from '../../src/seal.ts';

/** Every registered key type: tests that hold for all of them run once per type. */
export const types = Object.keys(keyTypes) as KeyTypeName[];

/** The scope tests use unless they need several. */
export const SCOPE = 'default';

/** Date.now() advancing 1 ms per call, so keys never share a creation millisecond. Restored by vi.restoreAllMocks. */
export function tickingClock(): void {
  let now = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => ++now);
}

const cleanups: (() => Promise<void>)[] = [];

/** A vault on a fresh, uniquely named database, closed and deleted by `cleanup`, and its scope SCOPE. */
export async function openVault(): Promise<{ vault: Vault; scope: Scope; name: string }> {
  const name = `test-${crypto.randomUUID()}`;
  const vault = await Vault.open({ name });
  cleanups.push(async () => {
    vault.close();
    await done(indexedDB.deleteDatabase(name));
  });
  return { vault, scope: vault.scope(SCOPE), name };
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

export async function rawRun<T>(name: string, stores: Store[], body: (tx: IDBTransaction) => IDBRequest<T> | void): Promise<T> {
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
export const deleteHeader = (name: string) => rawRun(name, ['meta'], (tx) => void tx.objectStore('meta').delete('header'));
export const readKey = (name: string, id: string, scope = SCOPE) =>
  rawRun<any>(name, ['keys'], (tx) => tx.objectStore('keys').get([scope, id]));
export const putKey = (name: string, record: object) => rawRun(name, ['keys'], (tx) => void tx.objectStore('keys').put(record));
export const readAll = async (name: string) => ({
  meta: await rawRun<unknown[]>(name, ['meta'], (tx) => tx.objectStore('meta').getAll()),
  keys: await rawRun<unknown[]>(name, ['keys'], (tx) => tx.objectStore('keys').getAll()),
});

/** Replaces the stored record of key `id` with `record` (whose own scope and id may differ). */
export const replaceKey = (name: string, id: string, record: object) =>
  rawRun(name, ['keys'], (tx) => {
    tx.objectStore('keys').delete([SCOPE, id]);
    tx.objectStore('keys').put(record);
  });

/**
 * Verifies without Vault's code: WebCrypto for ed25519; for secp256k1, which WebCrypto lacks, noble's own
 * defaults (the e2e test verifies with OpenSSL instead).
 */
export async function verifyOutsideVault(key: KeyInfo, signature: Signature, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  expect(signature.type).toBe(key.type);
  switch (key.type) {
    case 'ed25519': {
      const publicKey = await crypto.subtle.importKey('raw', key.publicKey, 'Ed25519', false, ['verify']);
      return crypto.subtle.verify('Ed25519', publicKey, signature.bytes, data);
    }
    case 'secp256k1':
      return secp256k1.verify(signature.bytes, data, key.publicKey);
  }
}

/**
 * Adds a self-consistent key record with the given public key, as any storage writer can: no secret needed.
 * `seal` defaults to an attacker's own fresh key of that type.
 */
export async function plantKey(
  name: string,
  type: KeyTypeName,
  publicKey: Bytes,
  sealWith?: GeneratedKey['seal'],
): Promise<KeyInfo> {
  const header = await readHeader(name);
  const fields: KeyFields = { v: 1, scope: SCOPE, id: await keyId(SCOPE, type, publicKey), type, publicKey, createdAt: Date.now() };
  const sealed = await seal(header.wrappingPublicKey, keyAad(fields), sealWith ?? (await keyTypes[type].generate()).seal);
  await putKey(name, { ...fields, sealed });
  return { id: fields.id, scope: SCOPE, type, publicKey, createdAt: new Date(fields.createdAt) } as KeyInfo;
}

export function flipBit<T extends Uint8Array>(bytes: T, index = bytes.length - 1): T {
  const copy = bytes.slice() as T;
  copy[index]! ^= 1;
  return copy;
}

export function done<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    if (req instanceof IDBOpenDBRequest) req.onblocked = () => reject(new Error('blocked'));
  });
}
