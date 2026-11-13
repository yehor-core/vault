import type { HeaderRecord } from './records.ts';

/**
 * How one context opens sealed keys: one per `Vault` instance, shared by every scope taken from it, never stored
 * or sent to another context (D-72).
 */
export class Unlock {
  /** The wrapping private key that opens the keys sealed to `header`. */
  wrappingPrivateKey(header: HeaderRecord): CryptoKey {
    return header.protection.privateKey; // unprotected: the header holds it
  }
}
