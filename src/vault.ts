import { Changes } from './changes.ts';
import { closedError, Connection } from './connection.ts';
import { protectVault } from './protect.ts';
import { createUnlockPasskey, presentUnlockPasskey, protectionSupport } from './protection.ts';
import { isScopeName, MAX_SCOPE_NAME_LENGTH } from './records.ts';
import { Scope } from './scope.ts';
import { clearAll, KEYS_STORE, META_STORE, readHeader } from './storage.ts';
import { Unlock, unlockVault } from './unlock.ts';

export interface OpenOptions {
  /** IndexedDB database name. Default: `vault`. */
  readonly name?: string;
}

/**
 * What a vault is, as this context sees it: `empty` (no key, never used or wiped), `unprotected`, or, for a
 * protected vault, `locked` or `unlocked` in this context.
 */
export type VaultState = 'empty' | 'unprotected' | 'locked' | 'unlocked';

/** What the page tells of protection before any prompt: never `supported` (D-75). */
export type ProtectionSupport = 'unsupported' | 'unknown';

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
   * Whether `protect()` can work here, as far as the page tells without a prompt: `unsupported` when it has no
   * WebAuthn or the browser reports no PRF extension; otherwise `unknown`, and only `protect()` tells for sure (the
   * authenticator the user picks may still lack PRF). Never `supported`. Opens no vault and shows no prompt.
   */
  static protectionSupport(): Promise<ProtectionSupport> {
    return protectionSupport();
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
    this.#unlock.dropIfStale(header);
    if (!header) return 'empty';
    if (header.protection.kind === 'none') return 'unprotected';
    return this.#unlock.isUnlocked(header) ? 'unlocked' : 'locked';
  }

  /**
   * Turns protection on, keeping every key: creates the vault's unlock credential, with a prompt started before any
   * await, and stores the vault sealed under it, atomically. Works on an empty vault too (D-67). This context is then
   * unlocked; every other context, and this one after a reload, is locked. A protected vault is `protected`; an
   * authenticator without PRF is `unsupported`; a declined prompt is `cancelled`. Whatever fails, the vault is
   * unchanged, and an unlock credential already created stays at its provider (D-76).
   */
  async protect(): Promise<void> {
    if (this.#connection.closed) throw closedError(); // before the prompt: a closed vault creates nothing
    const pending = createUnlockPasskey(); // the prompt, before any await
    const secret = await pending;
    await protectVault(this.#connection, this.#unlock, secret);
    this.#changes.notify();
  }

  /**
   * Unlocks this context with the vault's unlock credential: one discoverable prompt, started before any await. Every
   * sealed key of every scope taken from this instance then signs without a prompt, until `lock()` or `close()`.
   * Nothing is stored or sent to another context; each context unlocks on its own (D-72). Another credential, or a vault
   * that is empty or unprotected when the prompt is answered, is `not-found`; a declined prompt `cancelled`; an answer
   * without user verification or without a PRF result `unsupported`; an edited protected header `corrupted`. A failed
   * unlock changes nothing. Calls no `onChange` listener.
   */
  async unlock(): Promise<void> {
    if (this.#connection.closed) throw closedError(); // before the prompt: a closed vault prompts for nothing
    const pending = presentUnlockPasskey(); // the prompt, before any await
    const presented = await pending;
    await unlockVault(this.#connection, this.#unlock, presented);
  }

  /** Locks this context: sealed keys fail `sign` with `locked` until `unlock()`. Other contexts are unaffected. */
  lock(): void {
    if (this.#connection.closed) throw closedError();
    this.#unlock.lock();
  }

  /** Deletes every key of every scope and the vault itself, atomically. The vault is then empty, as if never used. */
  async wipe(): Promise<void> {
    await this.#connection.transact([META_STORE, KEYS_STORE], 'readwrite', async (tx) => clearAll(tx));
    this.#changes.notify();
  }

  /**
   * Calls `listener`, with no argument, after every successful `generate`, `delete`, `protect` and `wipe` in any context
   * that has this vault open, this one included, also when the call changed nothing. Read the vault again
   * there. Best effort: a notification can be lost or forged. Returns a function that stops the listener.
   */
  onChange(listener: () => void): () => void {
    if (this.#connection.closed) throw closedError();
    return this.#changes.subscribe(listener);
  }

  /** Releases the database connection and locks this context. Every later call, and every call still in flight, of the vault and its scopes throws. */
  close(): void {
    this.#unlock.lock();
    this.#connection.close();
    this.#changes.close();
  }
}
