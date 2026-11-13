import { equalBytes, type Bytes } from './bytes.ts';
import type { Connection } from './connection.ts';
import { VaultError } from './errors.ts';
import { presentUnlockPasskey, UNLOCK_KIND, unwrapWrappingKey, type PresentedUnlock } from './protection.ts';
import type { HeaderRecord } from './records.ts';
import { KEYS_STORE, META_STORE, readHeader } from './storage.ts';

/**
 * How one context opens sealed keys: one per `Vault` instance, shared by every scope taken from it, never stored
 * or sent to another context (D-72).
 */
export class Unlock {
  /** The unwrapped wrapping private key, with the wrapping public key of the header it belongs to (D-79). */
  #held: { readonly wrappingPublicKey: Bytes; readonly privateKey: CryptoKey } | undefined;
  /** The unlock credential named by the last header this context read or wrote (D-94). */
  #credentialId: Bytes | undefined;

  /** The unlock credential's credential id as of this context's last header read or write; undefined if none was named. */
  get credentialId(): Bytes | undefined {
    return this.#credentialId;
  }

  /** Keeps `privateKey`, which opens the keys sealed to `header`, a protected header this context read or wrote. */
  hold(header: HeaderRecord, privateKey: CryptoKey): void {
    this.see(header);
    this.#held = { wrappingPublicKey: header.wrappingPublicKey, privateKey };
  }

  /** Forgets the held key: this context is locked. */
  lock(): void {
    this.#held = undefined;
  }

  /**
   * Takes in the stored `header`, or its absence (undefined: the vault is empty); call with every header read or
   * write. Keeps the unlock credential it names (D-94), and drops the held key if the header is not the one it belongs
   * to: another context wiped, or wiped and protected again, since (D-79).
   */
  see(header: HeaderRecord | undefined): void {
    this.#credentialId = header?.protection.kind === UNLOCK_KIND ? header.protection.credentialId : undefined;
    if (this.#heldFor(header) === undefined) this.#held = undefined;
  }

  /** Forgets the unlock credential: the last header read failed. */
  forgetCredential(): void {
    this.#credentialId = undefined;
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
 * Reads the stored header and takes it in (`Unlock.see`); undefined: the vault is empty. A read that fails forgets the
 * unlock credential, so `unlock()` reads again, with no prompt, and reports the failure (D-94).
 */
export async function readHeaderInto(connection: Connection, unlock: Unlock): Promise<HeaderRecord | undefined> {
  let header: HeaderRecord | undefined;
  try {
    header = await connection.transact([META_STORE, KEYS_STORE], 'readonly', readHeader);
  } catch (error) {
    unlock.forgetCredential();
    throw error;
  }
  unlock.see(header);
  return header;
}

/**
 * Unlocks this context (D-94, D-77): one prompt for the unlock credential named by this context's last header read,
 * started before any await; then reads the header, checks the credential is the unlock credential it names, unwraps
 * the wrapping private key and holds it. Every failure leaves storage as it was.
 */
export async function unlockVault(connection: Connection, unlock: Unlock): Promise<void> {
  const asked = unlock.credentialId;
  if (asked === undefined) {
    await readHeaderInto(connection, unlock); // a malformed header fails here, corrupted
    throw new VaultError('not-found', "This instance's previous header read named no unlock credential");
  }
  const pending = presentUnlockPasskey(asked); // the prompt, before any await
  let presented: PresentedUnlock;
  try {
    presented = await pending;
  } catch (error) {
    if (error instanceof VaultError && error.code === 'cancelled')
      await failIfReplaced(connection, unlock, asked, error);
    throw error;
  }
  const header = await readHeaderInto(connection, unlock);
  if (!header) throw new VaultError('not-found', 'The vault is empty: it has no unlock credential');
  const { protection } = header;
  if (protection.kind !== UNLOCK_KIND)
    throw new VaultError('not-found', 'The vault is unprotected: it has no unlock credential');
  if (!equalBytes(protection.credentialId, presented.credentialId))
    throw new VaultError('not-found', "The presented credential is not the vault's unlock credential");
  if (presented.secret === undefined) throw new VaultError('unsupported', 'The authenticator returned no PRF result');
  const privateKey = await unwrapWrappingKey(presented.secret, { ...header, protection });
  unlock.hold(header, privateKey);
}

/**
 * After a declined prompt for `asked`: `not-found` if the stored header no longer names it. `NotAllowedError` also
 * covers a credential that no longer exists (D-59), so the header tells a stale id from a cancel.
 */
async function failIfReplaced(connection: Connection, unlock: Unlock, asked: Bytes, cause: VaultError): Promise<void> {
  await readHeaderInto(connection, unlock);
  const current = unlock.credentialId;
  if (current === undefined || !equalBytes(current, asked))
    throw new VaultError('not-found', "The unlock credential the prompt asked for is not the stored header's", {
      cause,
    });
}
