import { equalBytes, type Bytes } from './bytes.ts';
import type { Connection } from './connection.ts';
import { VaultError } from './errors.ts';
import { UNLOCK_KIND, unwrapWrappingKey, type PresentedUnlock } from './protection.ts';
import type { HeaderRecord } from './records.ts';
import { KEYS_STORE, META_STORE, readHeader } from './storage.ts';

/**
 * How one context opens sealed keys: one per `Vault` instance, shared by every scope taken from it, never stored
 * or sent to another context (D-72).
 */
export class Unlock {
  /** The unwrapped wrapping private key, with the wrapping public key of the header it belongs to (D-79). */
  #held: { readonly wrappingPublicKey: Bytes; readonly privateKey: CryptoKey } | undefined;

  /** Keeps `privateKey`, which opens the keys sealed to a protected header with `wrappingPublicKey`. */
  hold(wrappingPublicKey: Bytes, privateKey: CryptoKey): void {
    this.#held = { wrappingPublicKey, privateKey };
  }

  /** Forgets the held key: this context is locked. */
  lock(): void {
    this.#held = undefined;
  }

  /**
   * Drops the held key if the stored `header`, or its absence, is not the one it belongs to: another context wiped,
   * or wiped and protected again, since (D-79). Call with every header read for `state()` or `sign`.
   */
  dropIfStale(header: HeaderRecord | undefined): void {
    if (this.#heldFor(header) === undefined) this.#held = undefined;
  }

  /** Whether this context opens the keys of the stored `header` (undefined: the vault is empty) with a held key. */
  isUnlocked(header: HeaderRecord | undefined): boolean {
    return this.#heldFor(header) !== undefined;
  }

  /** The wrapping private key that opens the keys sealed to `header`; `locked` if this context doesn't hold it. */
  wrappingPrivateKey(header: HeaderRecord): CryptoKey {
    if (header.protection.kind === 'none') return header.protection.privateKey; // unprotected: the header holds it
    const held = this.#heldFor(header);
    if (held === undefined) throw new VaultError('locked', 'The vault is locked');
    return held.privateKey;
  }

  /** The held key, if it belongs to `header`. */
  #heldFor(header: HeaderRecord | undefined): { readonly privateKey: CryptoKey } | undefined {
    const held = this.#held;
    return held && header && equalBytes(held.wrappingPublicKey, header.wrappingPublicKey) ? held : undefined;
  }
}

/**
 * Unlocks this context with the credential the user presented, once its prompt is answered (D-73, D-77): reads the
 * header, checks the credential is the unlock credential it names, unwraps the wrapping private key and holds it. Every
 * failure leaves `unlock` and storage as they were.
 */
export async function unlockVault(connection: Connection, unlock: Unlock, presented: PresentedUnlock): Promise<void> {
  const header = await connection.transact([META_STORE, KEYS_STORE], 'readonly', readHeader);
  if (!header) throw new VaultError('not-found', 'The vault is empty: it has no unlock credential');
  const { protection } = header;
  if (protection.kind !== UNLOCK_KIND)
    throw new VaultError('not-found', 'The vault is unprotected: it has no unlock credential');
  if (!equalBytes(protection.credentialId, presented.credentialId))
    throw new VaultError('not-found', "The presented credential is not the vault's unlock credential");
  if (presented.secret === undefined) throw new VaultError('unsupported', 'The authenticator returned no PRF result');
  const privateKey = await unwrapWrappingKey(presented.secret, { ...header, protection });
  unlock.hold(header.wrappingPublicKey, privateKey);
}
