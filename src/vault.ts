import { closedError, Connection } from './connection.ts';
import { isScopeName } from './records.ts';
import { Scope } from './scope.ts';
import { clearAll, KEYS_STORE, META_STORE } from './storage.ts';

export interface OpenOptions {
  /** IndexedDB database name. Default: `vault`. */
  readonly name?: string;
}

/** A browser-native private-key store. Private keys never leave it; only signatures do. */
export class Vault {
  readonly #connection: Connection;

  private constructor(name: string) {
    this.#connection = new Connection(name);
  }

  static async open(options: OpenOptions = {}): Promise<Vault> {
    const vault = new Vault(options.name ?? 'vault');
    await vault.#connection.open();
    return vault;
  }

  /**
   * The scope `name`, empty until a key is generated in it. Synchronous: no I/O. `name` is a well-formed
   * string of 1 to 1024 UTF-16 code units, compared exactly.
   */
  scope(name: string): Scope {
    if (!isScopeName(name)) throw new TypeError('A scope name is a well-formed string of 1 to 1024 UTF-16 code units');
    if (this.#connection.closed) throw closedError();
    return new Scope(name, this.#connection);
  }

  /** Deletes every key of every scope and the vault itself, atomically. The vault is then empty, as if never used. */
  async wipe(): Promise<void> {
    await this.#connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => clearAll(tx));
  }

  /** Releases the database connection. Every later call, and every call still in flight, of the vault and its scopes throws. */
  close(): void {
    this.#connection.close();
  }
}
