import { openDatabase, transact, type Store } from './db.ts';

/** The IndexedDB connection a Vault and all its scopes share. Closing it ends every one of them. */
export class Connection {
  readonly #name: string;
  #db: Promise<IDBDatabase> | undefined;
  #closed = false;

  constructor(name: string) {
    this.#name = name;
  }

  get closed(): boolean {
    return this.#closed;
  }

  /** Every later call, and every call still in flight, throws. */
  close(): void {
    this.#closed = true;
    this.#db?.then((db) => db.close(), () => {});
    this.#db = undefined;
  }

  // The connection is taken right before each transaction, so a call in flight across close() sees the
  // documented InvalidStateError, and one across a versionchange reopens and gets 'incompatible'.
  async transact<T>(stores: Store[], mode: IDBTransactionMode, body: (tx: IDBTransaction) => Promise<T>): Promise<T> {
    const db = await this.open();
    if (this.#closed) throw closedError(); // closed while we awaited; from here to db.transaction is synchronous
    return transact(db, stores, mode, body);
  }

  open(): Promise<IDBDatabase> {
    if (this.#closed) return Promise.reject(closedError());
    if (!this.#db) {
      const pending = openDatabase(this.#name, () => {
        if (this.#db === pending) this.#db = undefined;
      });
      this.#db = pending;
      pending.catch(() => {
        if (this.#db === pending) this.#db = undefined;
      });
    }
    return this.#db;
  }
}

export function closedError(): DOMException {
  return new DOMException('The vault is closed', 'InvalidStateError');
}
