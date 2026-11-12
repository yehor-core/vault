import { VaultError } from './errors.ts';
import { corrupted, FORMAT_VERSION } from './records.ts';

export type Store = 'meta' | 'keys';

/**
 * Opens the vault database, creating it on first use. `onGone` fires once the connection
 * must not be used again: a newer format wants to upgrade, or the browser closed it.
 */
export function openDatabase(name: string, onGone: () => void): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.open(name, FORMAT_VERSION);
    } catch (cause) {
      return reject(unavailable(cause));
    }
    // Only 0 → 1 exists; a database at a higher version fails with VersionError instead.
    request.onupgradeneeded = () => {
      request.result.createObjectStore('meta');
      request.result.createObjectStore('keys', { keyPath: ['scope', 'id'] });
    };
    request.onsuccess = () => {
      const db = request.result;
      // Version 1 without our stores was created by something else (e.g. a bare indexedDB.open(name)).
      if (!db.objectStoreNames.contains('meta') || !db.objectStoreNames.contains('keys')) {
        db.close();
        return reject(corrupted('database has no Vault stores'));
      }
      db.onversionchange = () => {
        db.close(); // never block a newer format or a deletion; our next call reopens (D-40)
        onGone();
      };
      db.onclose = onGone;
      resolve(db);
    };
    request.onerror = () => {
      const { error } = request;
      reject(
        error?.name === 'VersionError'
          ? new VaultError('incompatible', 'Storage was written by a newer Vault format', { cause: error })
          : unavailable(error),
      );
    };
  });
}

/**
 * Runs `body` in one transaction and resolves after it commits; if `body` throws, nothing is written.
 * `body` may await only IndexedDB requests (or promises built from them): an await that settles in a
 * later task, crypto.subtle included, ends the transaction in Firefox and WebKit.
 */
export async function transact<T>(
  db: IDBDatabase,
  stores: Store[],
  mode: IDBTransactionMode,
  body: (tx: IDBTransaction) => Promise<T>,
): Promise<T> {
  let tx: IDBTransaction;
  try {
    tx = db.transaction(stores, mode);
  } catch (cause) {
    throw unavailable(cause);
  }
  const committed = new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(unavailable(tx.error));
  });
  committed.catch(() => {}); // awaited below; when body fails first this rejection is expected
  let result: T;
  try {
    result = await body(tx);
  } catch (error) {
    try {
      tx.abort();
    } catch {} // already aborted by the failed request
    throw error instanceof VaultError ? error : unavailable(error);
  }
  await committed;
  return result;
}

export function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function unavailable(cause: unknown): VaultError {
  return new VaultError('unavailable', 'IndexedDB is unavailable', { cause });
}
