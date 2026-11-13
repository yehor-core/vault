import { equalBytes, type Bytes } from './bytes.ts';
import { VaultError } from './errors.ts';
import type { HeaderRecord } from './records.ts';

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

  /** Whether this context opens the keys of the protected `header`. */
  isUnlocked(header: HeaderRecord): boolean {
    return this.#held !== undefined && equalBytes(this.#held.wrappingPublicKey, header.wrappingPublicKey);
  }

  /** The wrapping private key that opens the keys sealed to `header`; `locked` if this context doesn't hold it. */
  wrappingPrivateKey(header: HeaderRecord): CryptoKey {
    if (header.protection.kind === 'none') return header.protection.privateKey; // unprotected: the header holds it
    if (this.#held === undefined || !this.isUnlocked(header)) throw new VaultError('locked', 'The vault is locked');
    return this.#held.privateKey;
  }
}
