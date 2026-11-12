import { openDatabase, transact, type Store } from './db.ts';

/** One database connection, shared by a vault and all of its scopes; closing it ends them all. */
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

  async open(): Promise<void> {
    await this.#connection();
  }

  close(): void {
    this.#closed = true;
    this.#db?.then(
      (db) => db.close(),
      () => {},
    );
    this.#db = undefined;
  }

  // The connection is taken right before each transaction, so a call in flight across close() sees the
  // documented InvalidStateError, and one across a versionchange reopens: after a newer format's upgrade it
  // gets 'incompatible'; after the database was deleted (site data cleared, eviction, another tab) it gets a
  // new, empty database, where a write prepared before the deletion fails its header check and is redone.
  async transact<T>(stores: Store[], mode: IDBTransactionMode, body: (tx: IDBTransaction) => Promise<T>): Promise<T> {
    const db = await this.#connection();
    if (this.#closed) throw closedError(); // closed while we awaited; from here to db.transaction is synchronous
    return transact(db, stores, mode, body);
  }

  #connection(): Promise<IDBDatabase> {
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
