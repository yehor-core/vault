import { request, type Store } from './db.ts';
import { corrupted } from './readers.ts';
import { parseHeader, type HeaderRecord, type KeyRecord } from './records.ts';

// Record-level access inside a transaction; no crypto. Writes are not awaited: a failed request aborts
// the transaction, which transact() reports.

export const META_STORE = 'meta' satisfies Store;
export const KEYS_STORE = 'keys' satisfies Store;
export const HEADER_KEY = 'header';

/**
 * The header, or undefined for an empty vault. Key records without a header mean the header was
 * deleted, never that the vault is new: no legitimate write leaves one without the other. Any other
 * record in `meta` is corrupted (D-35): Vault writes none, and a later format must not trust a planted one.
 */
export async function readHeader(tx: IDBTransaction): Promise<HeaderRecord | undefined> {
  const meta = tx.objectStore(META_STORE);
  // count, not get: a header stored as `undefined` is present and malformed, not absent.
  // Two keys are enough: if one is the header, the other is not.
  const [present, value, keys] = await Promise.all([
    request(meta.count(HEADER_KEY)),
    request(meta.get(HEADER_KEY)),
    request(meta.getAllKeys(null, 2)),
  ]);
  const foreign = keys.find((key) => key !== HEADER_KEY);
  if (foreign !== undefined) throw corrupted(`meta: unexpected record ${keyName(foreign)}`);
  if (present) return parseHeader(value);
  if (await request(tx.objectStore(KEYS_STORE).count())) throw corrupted('key records exist without a vault header');
  return undefined;
}

export function getKeyRecord(tx: IDBTransaction, scope: string, id: string): Promise<unknown> {
  return request(tx.objectStore(KEYS_STORE).get([scope, id]));
}

export function listKeyRecords(tx: IDBTransaction, scope: string): Promise<unknown[]> {
  return request(tx.objectStore(KEYS_STORE).getAll(scopeRange(scope)));
}

/** The keys and the records of every scope, in key order. */
export async function listAllKeyRecords(tx: IDBTransaction): Promise<{ keys: IDBValidKey[]; values: unknown[] }> {
  const store = tx.objectStore(KEYS_STORE);
  const [keys, values] = await Promise.all([request(store.getAllKeys()), request(store.getAll())]);
  return { keys, values };
}

/** The keys of every key record, in key order. */
export function listAllKeys(tx: IDBTransaction): Promise<IDBValidKey[]> {
  return request(tx.objectStore(KEYS_STORE).getAllKeys());
}

export function addHeader(tx: IDBTransaction, header: HeaderRecord): void {
  tx.objectStore(META_STORE).add(header, HEADER_KEY);
}

/** Writes `header` over the stored one, or as the first. */
export function putHeader(tx: IDBTransaction, header: HeaderRecord): void {
  tx.objectStore(META_STORE).put(header, HEADER_KEY);
}

/** Writes `record` over the stored one of its scope and id. */
export function putKeyRecord(tx: IDBTransaction, record: KeyRecord): void {
  tx.objectStore(KEYS_STORE).put(record);
}

export function addKeyRecord(tx: IDBTransaction, record: KeyRecord): void {
  tx.objectStore(KEYS_STORE).add(record);
}

export function deleteKeyRecord(tx: IDBTransaction, scope: string, id: string): void {
  tx.objectStore(KEYS_STORE).delete([scope, id]);
}

export function clearAll(tx: IDBTransaction): void {
  tx.objectStore(META_STORE).clear();
  tx.objectStore(KEYS_STORE).clear();
}

/** An IndexedDB key as text that tells its kind: 7 and '7' differ, bytes read as hex. */
function keyName(key: IDBValidKey): string {
  if (typeof key === 'string') return JSON.stringify(key);
  if (typeof key === 'number') return String(key);
  if (key instanceof Date) return `Date ${key.toISOString()}`; // an invalid Date is no valid key
  if (Array.isArray(key)) return `[${key.map(keyName).join(', ')}]`;
  const bytes = ArrayBuffer.isView(key)
    ? new Uint8Array(key.buffer, key.byteOffset, key.byteLength)
    : new Uint8Array(key);
  return `bytes ${bytes.toHex()}`;
}

// [] sorts after every string in IndexedDB key order, so [scope] .. [scope, []] covers exactly one scope.
function scopeRange(scope: string): IDBKeyRange {
  return IDBKeyRange.bound([scope], [scope, []]);
}
