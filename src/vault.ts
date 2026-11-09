import { closedError, Connection } from './connection.ts';
import { isScopeName } from './records.ts';
import { Scope } from './scope.ts';
import { clearAll, KEYS_STORE, META_STORE } from './storage.ts';

export interface OpenOptions {
  /** IndexedDB database name. Default: `vault`. */
  readonly name?: string;
}

/**
 * A browser-native private-key store. Private keys never leave it; only signatures do. Keys live in named
 * scopes (`scope(name)`); the vault itself, its protection and `wipe` are shared by every scope.
 */
export class Vault {
  readonly #connection: Connection;

  private constructor(connection: Connection) {
    this.#connection = connection;
  }

  static async open(options: OpenOptions = {}): Promise<Vault> {
    const connection = new Connection(options.name ?? 'vault');
    await connection.open();
    return new Vault(connection);
  }

  /**
   * The keys of scope `name`: a well-formed string of 1 to 1024 UTF-16 code units. Synchronous, no I/O.
   * The Scope can't reach this Vault, so code handed only a Scope can't wipe the other scopes.
   */
  scope(name: string): Scope {
    if (this.#connection.closed) throw closedError();
    if (!isScopeName(name)) throw new TypeError('A scope name is a well-formed string of 1 to 1024 characters');
    return new Scope(name, this.#connection);
  }

  /** Deletes every key in every scope and the vault itself, atomically. The vault is then empty, as if never used. */
  async wipe(): Promise<void> {
    await this.#connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => clearAll(tx));
  }

  /** Releases the database connection. Every later call on this vault or its scopes, and every call in flight, throws. */
  close(): void {
    this.#connection.close();
  }
}
