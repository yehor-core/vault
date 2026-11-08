import { expect, vi } from 'vitest';
import { Vault, VaultError, type VaultErrorCode } from '../../src/index.ts';

/** Date.now() advancing 1 ms per call, so keys never share a creation millisecond. Restored by vi.restoreAllMocks. */
export function tickingClock(): void {
  let now = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => ++now);
}

const cleanups: (() => Promise<void>)[] = [];

/** A vault on a fresh, uniquely named database, closed and deleted by `cleanup`. */
export async function openVault(): Promise<{ vault: Vault; name: string }> {
  const name = `test-${crypto.randomUUID()}`;
  const vault = await Vault.open({ name });
  cleanups.push(async () => {
    vault.close();
    await done(indexedDB.deleteDatabase(name));
  });
  return { vault, name };
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
  expect(error).toMatchObject({ code });
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
export const readKey = (name: string, id: string) =>
  rawRun<any>(name, ['keys'], (tx) => tx.objectStore('keys').get(['default', id]));
export const readAll = async (name: string) => ({
  meta: await rawRun<unknown[]>(name, ['meta'], (tx) => tx.objectStore('meta').getAll()),
  keys: await rawRun<unknown[]>(name, ['keys'], (tx) => tx.objectStore('keys').getAll()),
});

/** Replaces the stored record of key `id` with `record` (whose own scope and id may differ). */
export const replaceKey = (name: string, id: string, record: object) =>
  rawRun(name, ['keys'], (tx) => {
    tx.objectStore('keys').delete(['default', id]);
    tx.objectStore('keys').put(record);
  });

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
