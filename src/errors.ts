export type VaultErrorCode =
  /** IndexedDB or WebCrypto failed in a way a retry may fix (I/O, quota, storage cleared, key generation). */
  | 'unavailable'
  /** A stored record is malformed, tampered with, or does not decrypt or verify. Vault never repairs it. */
  | 'corrupted'
  /**
   * Storage was written by a newer Vault build: a newer format, or a key type this build doesn't know.
   * This build doesn't read it; reload a newer build. (`delete` still removes a key of an unknown type.)
   */
  | 'incompatible'
  /** No key with this id. */
  | 'not-found';

/** Every failure Vault reports. Branch on `code`; retry only when `retryable`. */
export class VaultError extends Error {
  override readonly name = 'VaultError';
  readonly code: VaultErrorCode;
  readonly retryable: boolean;

  constructor(code: VaultErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
    this.retryable = code === 'unavailable';
  }
}
