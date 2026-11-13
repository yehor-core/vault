import { Changes } from './changes.ts';
import { closedError, Connection } from './connection.ts';
import { isScopeName, MAX_SCOPE_NAME_LENGTH } from './records.ts';
import { Scope } from './scope.ts';
import { clearAll, KEYS_STORE, META_STORE, readHeader } from './storage.ts';
import { Unlock } from './unlock.ts';

export interface OpenOptions {
  /** IndexedDB database name. Default: `vault`. */
  readonly name?: string;
}

/**
 * What a vault is, as this context sees it: `empty` (no key, never used or wiped), `unprotected`, or, for a
 * protected vault, `locked` or `unlocked` in this context.
 */
export type VaultState = 'empty' | 'unprotected' | 'locked' | 'unlocked';

/** A browser-native private-key store. Private keys never leave it; only signatures do. */
export class Vault {
  readonly #connection: Connection;
  readonly #changes: Changes;
  /** This context's own: every scope taken from this instance shares it (D-72). */
  readonly #unlock = new Unlock();

  private constructor(connection: Connection, changes: Changes) {
    this.#connection = connection;
    this.#changes = changes;
  }

  static async open(options: OpenOptions = {}): Promise<Vault> {
    const name = options.name ?? 'vault';
    const connection = new Connection(name);
    await connection.open();
    return new Vault(connection, new Changes(name)); // the channel opens only for a vault that opened
  }

  /**
   * The scope `name`, empty until a key is generated in it. Synchronous: no I/O. `name` is a well-formed
   * string of 1 to MAX_SCOPE_NAME_LENGTH (1024) UTF-16 code units, compared exactly.
   */
  scope(name: string): Scope {
    if (!isScopeName(name))
      throw new TypeError(`A scope name is a well-formed string of 1 to ${MAX_SCOPE_NAME_LENGTH} UTF-16 code units`);
    if (this.#connection.closed) throw closedError();
    return new Scope(name, this.#connection, this.#changes, this.#unlock);
  }

  /**
   * The vault's state. A vault deleted under it (site data cleared, eviction) is `empty`, and the next `generate`
   * creates an unprotected one: an application that expects protection checks this first. Never prompts.
   */
  async state(): Promise<VaultState> {
    const header = await this.#connection.transact([META_STORE, KEYS_STORE], 'readonly', readHeader);
    return header ? 'unprotected' : 'empty';
  }

  /** Deletes every key of every scope and the vault itself, atomically. The vault is then empty, as if never used. */
  async wipe(): Promise<void> {
    await this.#connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => clearAll(tx));
    this.#changes.notify();
  }

  /**
   * Calls `listener`, with no argument, after every successful `generate`, `delete` and `wipe` in any context
   * that has this vault open, this one included, also when the call changed nothing. Read the vault again
   * there. Best effort: a notification can be lost or forged. Returns a function that stops the listener.
   */
  onChange(listener: () => void): () => void {
    if (this.#connection.closed) throw closedError();
    return this.#changes.subscribe(listener);
  }

  /** Releases the database connection. Every later call, and every call still in flight, of the vault and its scopes throws. */
  close(): void {
    this.#connection.close();
    this.#changes.close();
  }
}
