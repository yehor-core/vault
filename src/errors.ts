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
  | 'not-found'
  /**
   * A key's prompt ended without an answer: the user declined it, it timed out, or the authenticator holds no such
   * credential (lost, deleted or replaced at its provider). No engine tells these apart (D-59). Not retryable: let
   * the user try again when they choose; a key that keeps failing this way may be gone, so offer to delete it.
   */
  | 'cancelled'
  /**
   * The authenticator can't verify the user (PIN or biometric), or answered without verifying them (D-59). Not
   * retryable: ask the user for an authenticator that verifies them.
   */
  | 'unsupported';

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
